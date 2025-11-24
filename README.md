# SAML Service Provider (SP) for Shibboleth

This is a sample Flask-based SAML Service Provider (SP) designed to integrate with a Shibboleth Identity Provider (IdP).
It uses the `python3-saml` library to handle SAML requests and responses.

## Prerequisites

- Python 3.10+
- An installed and configured Shibboleth IdP instance.

## 1. Project Setup

Follow these steps to get the service provider running.

### Clone the Repository

```bash
git clone https://github.com/sam-packer/SimpleSAMLsp
cd SimpleSAMLsp
```

### Create a Virtual Environment

It's recommended to run the application in a virtual environment.

```bash
uv venv
source .venv/bin/activate
# On Windows, use: .venv\Scripts\activate
```

### Install Dependencies

Install the required Python packages using `pip`.

```bash
uv sync
```

## 2. SP Configuration

Configuration for the service provider is handled in the `saml/` directory.

### Generate SP Certificate and Key

The SP needs its own certificate and private key to sign and encrypt/decrypt SAML messages. You can generate a
self-signed certificate for testing purposes.

```bash
mkdir -p saml
openssl req -new -x509 -days 3652 -nodes -out saml/sp.crt -keyout saml/sp.key
```

This will create `sp.crt` (public certificate) and `sp.key` (private key) in the `saml/` directory. The application will
load these files automatically.

### Configure `settings.json`

The primary configuration file is `saml/settings.json`. You need to populate it with information from your Shibboleth
IdP and your SP's own details.

Here is a template to get you started. You must replace the placeholder values.

```json
{
  "strict": true,
  "debug": true,
  "sp": {
    "entityId": "http://localhost:5000/metadata",
    "assertionConsumerService": {
      "url": "http://localhost:5000/acs",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "singleLogoutService": {
      "url": "http://localhost:5000/sls",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  },
  "idp": {
    "entityId": "https://your-idp.example.com/idp/shibboleth",
    "singleSignOnService": {
      "url": "https://your-idp.example.com/idp/profile/SAML2/Redirect/SSO",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "https://your-idp.example.com/idp/profile/SAML2/Redirect/SLO",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "MIIC...YourIdpSigningCertificate...=="
  }
}
```

Where to find these values:

- `sp.entityId`: This is a unique identifier for your application. A common practice is to use the URL to your
  metadata, e.g., `http://localhost:5000/metadata`.
- `sp.assertionConsumerService.url`: This is the endpoint on your SP where the IdP will send SAML assertions. For
  this app, it is `http://localhost:5000/acs`.
- `idp.entityId`: The entityID of your Shibboleth IdP. You can find this in your IdP's `idp-metadata.xml`.
- `idp.singleSignOnService.url`: The IdP's SSO URL. You can also find this in `idp-metadata.xml`.
- `idp.x509cert`: The public signing certificate of your IdP. You can get this from your IdP's metadata or directly
  from the signing certificate file (e.g., `idp-signing.crt`) on the IdP server. Ensure it's a single line without
  headers/footers.

## 3. Shibboleth IdP Configuration

Your Shibboleth IdP needs to be configured to recognize your new SP.

### Get SP Metadata

First, run the Flask application (see next step). While it's running, access the metadata endpoint in your browser or
with `curl`:

```bash
curl http://localhost:5000/metadata
```

This will output the SP's SAML metadata as XML. Save this to a file (e.g., `sp-metadata.xml`).

### Add SP Metadata to Shibboleth

1. Copy the `sp-metadata.xml` file to your Shibboleth IdP's `metadata` directory (e.g., `/opt/shibboleth-idp/metadata`).

2. Add a new metadata provider in `metadata-providers.xml` (e.g., in `/opt/shibboleth-idp/conf`):

   ```xml
   <MetadataProvider id="SPLocal" xsi:type="FilesystemMetadataProvider" metadataFile="%{idp.home}/metadata/sp-metadata.xml"/>
   ```
   *Make sure to add this inside the `shibboleth.MetadataResolver` definition.*

3. Reload the IdP Metadata Service: Use the `reload-service.sh` script or restart your servlet container to apply
   the changes.

### Configure Attribute Release

Shibboleth will not release any user attributes to the SP by default. You must configure an attribute filter policy.

1. Open `attribute-filter.xml` (e.g., in `/opt/shibboleth-idp/conf`).
2. Add a new `AttributeFilterPolicy` for your SP. The `policyRequirementRule` should match your SP's entityID.

   ```xml
   <!-- Release attributes to our new SP -->
   <AttributeFilterPolicy id="release-to-our-sp">
       <PolicyRequirementRule xsi:type="Requester" value="http://localhost:5000/metadata" />

       <!-- Release Transient ID as the NameID -->
       <AttributeRule attributeID="transientId">
           <PermitValueRule xsi:type="ANY" />
       </AttributeRule>

       <!-- Release Email Address -->
       <AttributeRule attributeID="mail">
           <PermitValueRule xsi:type="ANY" />
       </AttributeRule>

       <!-- Release First Name -->
       <AttributeRule attributeID="givenName">
           <PermitValueRule xsi:type="ANY" />
       </AttributeRule>
   </AttributeFilterPolicy>
   ```

3. Reload the attribute filter service.

## 4. Running the Application

Once configured, you can run the Flask app.

```bash
uv run app.py
```

The application will be available at `http://localhost:5000`.

- `http://localhost:5000/`: The home page with a link to log in.
- `http://localhost:5000/login`: This link will redirect you to the Shibboleth IdP for authentication.
- `http://localhost:5000/metadata`: View the SP metadata.
