const _PGP_BEGIN = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const _PGP_END = "-----END PGP PRIVATE KEY BLOCK-----";

type SecretPattern = {
  name: string;
  regex: RegExp;
};

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key ID",
    regex: /\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    name: "AWS Secret Access Key",
    regex:
      /(?:aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?/gi,
  },
  {
    name: "GitHub Token",
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b/g,
  },
  {
    name: "GitHub Fine-Grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
  },
  {
    name: "GitLab Tokens",
    regex:
      /\b(?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bGR1348941[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bglcbt-(?:[0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bglimt-[A-Za-z0-9_\-]{25}(?!\w)\b|\bglptt-[A-Za-z0-9_\-]{40}(?!\w)\b|\bglagent-[A-Za-z0-9_\-]{50,1024}(?!\w)\b|\bgloas-[A-Za-z0-9_\-]{64}(?!\w)\b/g,
  },
  {
    name: "Slack Token",
    regex: /xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+/gi,
  },
  {
    name: "Slack Webhook",
    regex:
      /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/gi,
  },
  {
    name: "Discord Bot Token",
    regex:
      /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g,
  },
  {
    name: "Discord Webhook",
    regex:
      /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[A-Za-z0-9_-]{30,}/g,
  },
  {
    name: "Telegram Bot Token",
    regex: /\b\d{8,10}:[0-9A-Za-z_-]{35}\b/g,
  },
  {
    name: "Stripe Secret Key",
    regex: /\b(?:r|s)k_(?:live|test)_[0-9A-Za-z]{24,}\b/g,
  },
  {
    name: "Stripe Publishable Key",
    regex: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: "Twilio Account SID",
    regex: /\bAC[0-9a-fA-F]{32}\b/g,
  },
  {
    name: "Twilio API Key SID",
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
  },
  {
    name: "Twilio Auth Token",
    regex:
      /\b(?:twilio_)?auth_?token['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?/gi,
  },
  {
    name: "SendGrid API Key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  },
  {
    name: "NPM Token",
    regex: /\bnpm_[A-Za-z0-9]{30,}\b/g,
  },
  {
    name: "NPM .npmrc Auth Token",
    regex: /\/\/[^\n]+\/:_authToken=\s*((npm_.+)|([A-Fa-f0-9-]{36}))/g,
  },
  {
    name: "PyPI Token",
    regex:
      /\bpypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9-_]{70,}\b/g,
  },
  {
    name: "Azure Storage Connection String",
    regex:
      /DefaultEndpointsProtocol=(?:http|https);AccountName=[A-Za-z0-9\-]+;AccountKey=([A-Za-z0-9+/=]{40,});EndpointSuffix=core\.windows\.net/g,
  },
  {
    name: "Azure Storage Account Key",
    regex: /AccountKey=[A-Za-z0-9+/=]{88}/g,
  },
  {
    name: "Azure SAS Token",
    regex: /[\?&]sv=\d{4}-\d{2}-\d{2}[^ \n]*?&sig=[A-Za-z0-9%+/=]{16,}/g,
  },
  {
    name: "Artifactory Credentials",
    regex: /(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\s|\"|$)/g,
  },
  {
    name: "Artifactory Encrypted Password",
    regex: /(?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|\"|$)/g,
  },
  {
    name: "Cloudant URL Credential",
    regex:
      /https?:\/\/[\w\-]+:([0-9a-f]{64}|[a-z]{24})@[\w\-]+\.cloudant\.com/gi,
  },
  {
    name: "SoftLayer API Token",
    regex: /https?:\/\/api\.softlayer\.com\/soap\/(?:v3|v3\.1)\/([a-z0-9]{64})/gi,
  },
  {
    name: "JWT Token",
    regex:
      /\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*?\b/g,
  },
  {
    name: "Private Key (PEM)",
    regex:
      /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----\s*\n(?:(?:[A-Za-z0-9\-]+:[^\n]*\n)*\s*)?(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    name: "OpenSSH Private Key",
    regex:
      /-----BEGIN OPENSSH PRIVATE KEY-----\s*\n(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END OPENSSH PRIVATE KEY-----/g,
  },
  {
    name: "PGP Private Key",
    regex:
      new RegExp(
        `${_PGP_BEGIN}\\s*\\n(?:(?:[A-Za-z0-9\\-]+:[^\\n]*\\n)*\\s*)?(?:[A-Za-z0-9+/=]{40,}\\s*\\n)+${_PGP_END}`,
        "g",
      ),
  },
  {
    name: "SSH2 Encrypted Private Key",
    regex:
      /-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\s*\n(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END SSH2 ENCRYPTED PRIVATE KEY-----/g,
  },
  {
    name: "PuTTY Private Key",
    regex: /(?:^|\n)PuTTY-User-Key-File-\d+:\s*\S+/g,
  },
  {
    name: "Google API Key",
    regex: /\bAIza[0-9A-Za-z\-_\\]{32,40}\b/g,
  },
  {
    name: "Google OAuth Token",
    regex: /\bya29\.[0-9A-Za-z\-_]{20,}\b/g,
  },
  {
    name: "Anthropic API Key",
    regex: /\bsk-ant-api\d+-[A-Za-z0-9_-]{90,}\b/g,
  },
  {
    name: "OpenAI API Key",
    regex:
      /\b(?:openai[_-]?api[_-]?key\s*[:=]\s*)?sk-(?:proj-|org-)?[A-Za-z0-9-_]{20,}\b/gi,
  },
  {
    name: "Password Assignment",
    regex: /\b(pass(word)?|pwd)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]/gi,
  },
  {
    name: "Mailchimp API Key",
    regex: /\b[0-9a-z]{32}-us[0-9]{1,2}\b/g,
  },
  {
    name: "Basic Auth Credentials",
    regex: /:\/\/[^:/?#\[\]@!$&'()*+,;=\s]+:([^:/?#\[\]@!$&'()*+,;=\s]+)@/g,
  },
  {
    name: "Databricks PAT",
    regex: /\bdapi[A-Za-z0-9]{32}\b/g,
  },
  {
    name: "Firebase FCM Server Key",
    regex: /\bAAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}\b/g,
  },
  {
    name: "Shopify Token",
    regex: /\bshp(?:at|pa|ss)_[0-9a-f]{32}\b/g,
  },
  {
    name: "Notion Integration Token",
    regex: /\bsecret_[A-Za-z0-9]{32,}\b/g,
  },
  {
    name: "Linear API Key",
    regex: /\blin_api_[A-Za-z0-9]{40}\b/g,
  },
  {
    name: "Mapbox Access Token",
    regex: /\b[ps]k\.[A-Za-z0-9\-_.]{30,}\b/g,
  },
  {
    name: "Dropbox Access Token",
    regex: /\bsl\.[A-Za-z0-9_-]{120,}\b/g,
  },
  {
    name: "DigitalOcean Personal Access Token",
    regex: /\bdop_v1_[a-f0-9]{64}\b/g,
  },
  {
    name: "Square Access Token",
    regex: /\bEAAA[A-Za-z0-9]{60}\b/g,
  },
  {
    name: "Square OAuth Secret",
    regex: /\bsq0csp-[0-9A-Za-z_\-]{43}\b/g,
  },
  {
    name: "Airtable Personal Access Token",
    regex: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g,
  },
  {
    name: "Facebook Access Token",
    regex: /\bEAA[A-Za-z0-9]{30,}\b/g,
  },
  {
    name: "Bearer Token",
    regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/g,
  },
];

export type { SecretPattern };
export { SECRET_PATTERNS };
