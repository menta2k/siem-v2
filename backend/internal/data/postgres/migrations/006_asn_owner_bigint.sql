-- AS numbers are 32-bit unsigned (RFC 6793): the top of the range does not
-- fit a signed int4. Found the honest way — the first real iptoasn snapshot
-- carries AS4294901909 and the insert refused.
ALTER TABLE asn_owner ALTER COLUMN asn TYPE BIGINT;
