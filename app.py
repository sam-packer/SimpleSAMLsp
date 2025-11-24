from flask import Flask, request, redirect, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import json, os, traceback, base64, xml.etree.ElementTree as ET
from copy import deepcopy

app = Flask(__name__)
app.secret_key = os.getenv("SAML_DEMO_SECRET", "saml-demo-secret")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def prepare_flask_request(req):
    """Convert Flask request to python3-saml format."""
    return {
        "https": "on" if req.is_secure else "off",
        "http_host": req.host,
        "server_port": req.environ.get("SERVER_PORT"),
        "script_name": req.path,
        "get_data": req.args.copy(),
        "post_data": req.form.copy(),
    }


def load_saml_settings():
    """Load and merge SAML settings."""
    saml_dir = os.path.join(os.getcwd(), "saml")
    with open(os.path.join(saml_dir, "settings.json")) as f:
        settings_data = json.load(f)

    adv_path = os.path.join(saml_dir, "advanced_settings.json")
    if os.path.exists(adv_path):
        with open(adv_path) as f:
            settings_data.update(json.load(f))

    cert_path, key_path = os.path.join(saml_dir, "sp.crt"), os.path.join(saml_dir, "sp.key")
    settings_data.setdefault("sp", {})
    if os.path.exists(cert_path):
        with open(cert_path) as f:
            settings_data["sp"]["x509cert"] = f.read().strip()
    if os.path.exists(key_path):
        with open(key_path) as f:
            settings_data["sp"]["privateKey"] = f.read().strip()
    return settings_data


def parse_saml_status(decoded_xml_bytes):
    """Extract <StatusCode> / <StatusMessage> for friendly errors."""
    try:
        xml = decoded_xml_bytes.decode("utf-8", errors="ignore")
        root = ET.fromstring(xml)
        ns = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"}
        status = root.find("samlp:Status", ns)
        if status is None:
            return None, None, None, xml
        code_el = status.find("samlp:StatusCode", ns)
        sub_el = code_el.find("samlp:StatusCode", ns) if code_el is not None else None
        msg_el = status.find("samlp:StatusMessage", ns)
        return (
            code_el.get("Value") if code_el is not None else None,
            sub_el.get("Value") if sub_el is not None else None,
            msg_el.text.strip() if msg_el is not None and msg_el.text else None,
            xml,
        )
    except Exception:
        return None, None, None, decoded_xml_bytes.decode("utf-8", errors="ignore")


@app.route("/")
def index():
    acs_url = f"{request.url_root.rstrip('/')}/acs"
    return render_template("index.html", acs_url=acs_url)


@app.route("/login")
def login():
    req = prepare_flask_request(request)
    settings_data = load_saml_settings()
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_data)

    redirect_url = auth.login()
    print("=== AuthnRequest XML ===")
    print(auth.get_last_request_xml())
    print("=========================")
    return redirect(redirect_url)


@app.route("/acs", methods=["POST"])
def acs():
    req = prepare_flask_request(request)
    relay_state = request.form.get("RelayState")
    try:
        settings_data = load_saml_settings()
        auth = OneLogin_Saml2_Auth(req, old_settings=settings_data)
        auth.process_response()
        errors = auth.get_errors()

        saml_response = request.form.get("SAMLResponse")
        decoded = base64.b64decode(saml_response) if saml_response else None

        if errors or not auth.is_authenticated():
            status_code, sub_status, status_msg, xml = (None, None, None, None)
            if decoded:
                status_code, sub_status, status_msg, xml = parse_saml_status(decoded)
            return render_template(
                "error.html",
                reason=auth.get_last_error_reason(),
                friendly="Access was denied by your identity provider.",
                status_code=status_code,
                sub_status=sub_status,
                status_message=status_msg,
                raw_xml=xml,
                relay_state=relay_state,
            ), 403

        return render_template(
            "success.html",
            nameid=auth.get_nameid(),
            attributes=auth.get_attributes(),
            session_index=auth.get_session_index(),
        )

    except Exception as e:
        traceback.print_exc()
        return render_template(
            "error.html",
            friendly="Something went wrong processing your sign-in.",
            reason=str(e),
        ), 500


@app.route("/metadata")
def metadata():
    saml_dir = os.path.join(os.getcwd(), "saml")
    settings_data = load_saml_settings()
    saml_settings = OneLogin_Saml2_Settings(settings_data, custom_base_path=saml_dir)

    metadata_xml = saml_settings.get_sp_metadata()
    if isinstance(metadata_xml, (bytes, bytearray)):
        metadata_xml = metadata_xml.decode("utf-8", errors="replace")

    NS = {
        "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    ET.register_namespace("md", NS["md"])
    ET.register_namespace("ds", NS["ds"])

    try:
        root = ET.fromstring(metadata_xml)
    except ET.ParseError as e:
        return f"Error parsing metadata XML: {e}", 500

    sp = root.find("md:SPSSODescriptor", NS)
    if sp is None:
        return "Metadata missing SPSSODescriptor", 500

    # Ensure encryption descriptor
    has_encryption = any(kd.get("use") == "encryption" for kd in sp.findall("md:KeyDescriptor", NS))
    if not has_encryption:
        kd_sign = sp.find("md:KeyDescriptor", NS)
        if kd_sign is not None:
            kd_enc = deepcopy(kd_sign)
            kd_enc.set("use", "encryption")
            sp.append(kd_enc)
            print("Added <md:KeyDescriptor use='encryption'>")

    # Ensure NameIDFormat
    if not sp.find("md:NameIDFormat", NS):
        nameid = ET.SubElement(sp, f"{{{NS['md']}}}NameIDFormat")
        nameid.text = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        print("Added <md:NameIDFormat>")

    # Mark ACS as default
    for acs in sp.findall("md:AssertionConsumerService", NS):
        if acs.get("isDefault") is None:
            acs.set("isDefault", "true")

    # Add SingleLogoutService if missing
    if sp.find("md:SingleLogoutService", NS) is None:
        sls = ET.SubElement(sp, f"{{{NS['md']}}}SingleLogoutService")
        sls.set("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
        sls.set("Location", "https://sp.sampacker.com/sls")
        print("Added <md:SingleLogoutService>")

    sp.set("WantAssertionsSigned", "true")

    out = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return out, 200, {"Content-Type": "text/xml; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
