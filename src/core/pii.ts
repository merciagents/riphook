import { luhnCheck } from "./luhn.js";

type PiiMatch = {
  type: "pii_ssn" | "pii_email" | "pii_phone" | "pii_credit_card";
  value: string;
};

const SSN_REGEX = /\b\d{3}-?\d{2}-?\d{4}\b/g;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PHONE_CANDIDATE_REGEX =
  /\b(?:\+?\d{1,3}[-. ]?)?(?:\(?\d{2,4}\)?[-. ]?)?\d{3}[-. ]?\d{4}\b/g;
const CREDIT_CARD_CANDIDATE_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

function detectPii(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];

  let result: RegExpExecArray | null;
  const ssn = new RegExp(SSN_REGEX.source, SSN_REGEX.flags);
  while ((result = ssn.exec(text)) !== null) {
    matches.push({ type: "pii_ssn", value: result[0] });
  }

  const email = new RegExp(EMAIL_REGEX.source, EMAIL_REGEX.flags);
  while ((result = email.exec(text)) !== null) {
    matches.push({ type: "pii_email", value: result[0] });
  }

  const phone = new RegExp(PHONE_CANDIDATE_REGEX.source, PHONE_CANDIDATE_REGEX.flags);
  while ((result = phone.exec(text)) !== null) {
    matches.push({ type: "pii_phone", value: result[0] });
  }

  const card = new RegExp(
    CREDIT_CARD_CANDIDATE_REGEX.source,
    CREDIT_CARD_CANDIDATE_REGEX.flags,
  );
  while ((result = card.exec(text)) !== null) {
    const candidate = result[0] ?? "";
    if (candidate && luhnCheck(candidate)) {
      matches.push({ type: "pii_credit_card", value: candidate });
    }
  }

  return matches;
}

function containsPii(text: string): boolean {
  return detectPii(text).length > 0;
}

export type { PiiMatch };
export { detectPii, containsPii };
