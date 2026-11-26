// OpenPGP ASCII armor tags, used to validate the wire format before parsing.
const tag = (boundary, label) => `-----${boundary} PGP ${label}-----`;
export const publicKeyStart = tag('BEGIN', 'PUBLIC KEY BLOCK');
export const publicKeyEnd = tag('END', 'PUBLIC KEY BLOCK');
export const messageStart = tag('BEGIN', 'MESSAGE');
export const messageEnd = tag('END', 'MESSAGE');
