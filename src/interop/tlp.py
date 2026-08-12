"""The TLP:CLEAR marking-definition object (FR-IO-06).

`stix2==3.0.1` ships only TLP 1.0 markings (TLP_WHITE/GREEN/AMBER/RED); TLP:CLEAR is
TLP 2.0's replacement for TLP:WHITE and is not in the library. Every exported object
defaults to this marking (interoperability-layer/design.md Part 3) -- per-source TLP
propagation is out of scope for this build (design spec decision 4).

This is the fixed OASIS reference object, parsed rather than hand-constructed field by
field, so a typo cannot silently produce a marking with the wrong id -- a consumer
matching against the well-known TLP:CLEAR id would then treat our objects as unmarked.
Source: cti-stix-common-objects/extension-definition-specifications/tlp-2.0/examples/
tlp-clear.json (OASIS).
"""

import stix2

_TLP_CLEAR_JSON = """
{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "created": "2022-10-01T00:00:00.000Z",
    "name": "TLP:CLEAR",
    "extensions": {
        "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
            "extension_type": "property-extension",
            "tlp_2_0": "clear"
        }
    }
}
"""

TLP_CLEAR = stix2.parse(_TLP_CLEAR_JSON, allow_custom=True)
