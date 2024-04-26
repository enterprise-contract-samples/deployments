package provenance

import rego.v1

import data.lib

# METADATA
# title: SLSA Provenance v0.2
# description: Verify the associated SLSA Provenance is in the 0.2 format.
# custom:
#   short_name: format_v0_2
#
deny contains result if {
    some error in _format_errors
    result := {"msg": error, "metadata": {"code": "provenance.format_v0_2"}}
}

_format_erros contains error if {
    count(input.attestations) == 0
    error := "No attestations were found"
}

_format_errors contains error if {
    count(input.attestations) > 0
    provenance_attestations := [attestation |
        some attestation in input.attestations
        attestation.statement.predicateType == "https://slsa.dev/provenance/v0.2"
    ]
    count(provenance_attestations) == 0
    error := "No SLSA Provenace v0.2 attestations found"
}

# METADATA
# title: Builder ID
# description: Verify the builder ID in the SLSA Provenance v0.2 is expected.
# custom:
#   short_name: builder_id
#
deny contains result if {
    some error in _builder_id_errors
    result := {"msg": error, "metadata": {"code": "provenance.builder_id"}}
}

_builder_id_errors contains error if {
    allowed_builders := lib.rule_data("allowed_builders")

    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v0.2"
    builder_id := object.get(attestation.statement, ["predicate", "builder", "id"], "MISSING")
    not builder_id in allowed_builders
    error := sprintf("Builder ID %q is not one of the allowed values: %s", [builder_id, allowed_builders])
}

# METADATA
# title: Identity
# description: Verify the identity used in the signature of the SLSA Provenance attestation.
# custom:
#   short_name: identity
#
deny contains result if {
    some error in _identity_errors
    result := {"msg": error, "metadata": {"code": "provenance.identity"}}
}

_identity_errors contains error if {
    count(_identities) == 0
    error := "No identities associated with the SLSA Provenance attestation"
}

_identity_errors contains error if {
    allowed_builders := lib.rule_data("allowed_builders")

    some identity in _identities
    not identity in allowed_builders
    error := sprintf("Identity %q is not one of the allowed identities: %s", [identity, allowed_builders])
}

_identities contains identity if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v0.2"
    some signature in attestation.signatures
    some cert in crypto.x509.parse_certificates(signature.certificate)
    some identity in cert.URIStrings
}
