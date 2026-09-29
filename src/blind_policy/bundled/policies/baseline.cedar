// Hand-written Cedar sits alongside the compiled YAML regimes.
//
// Nothing is readable unless some regime file permits it: Cedar denies by
// default. This file adds rules that hold whatever any regime says.

// Special-category content (diagnoses, procedures, free-text notes) decrypts
// for the data owner only. Agents can still count and filter it, encrypted.
@id("baseline.sensitive_decrypt_owner_only")
@regime("BASELINE")
@reason("Special-category content decrypts for the data owner only")
forbid (
  principal,
  action == BI::Action::"decrypt",
  resource is BI::Field
) when {
  resource.sensitivity == "sensitive"
} unless {
  principal in BI::Role::"data_owner"
};
