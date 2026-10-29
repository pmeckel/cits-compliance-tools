"""
Shared DENM helpers: human-readable event types (cause and sub cause, name and code).

A decoded DENM event type looks like  {'ccAndScc': ('roadworks3', 4)}:
the CHOICE alternative name carries the cause name and its cause code number
as a suffix, the value is the sub cause code. asn1tools does not expose the
names of the named sub cause values, so they are read directly from the
ETSI-ITS-CDD.asn file (CauseCodeChoice and the *SubCauseCode INTEGER types).
This keeps the names in sync with whichever CDD version is in use.
"""

import re
from pathlib import Path

CDD_FILE = 'ETSI-ITS-CDD.asn'

_CHOICE_RE = re.compile(r'CauseCodeChoice\s*::=\s*CHOICE\s*\{(.*?)\n\s*\}', re.S)
_ALT_RE = re.compile(r'^\s*([\w-]+?)(\d+)\s+([\w-]+)\s*,?\s*$')
_SUBTYPE_RE = re.compile(r'^([\w-]+SubCauseCode)\s*::=\s*INTEGER\s*\{(.*?)\}', re.S | re.M)
_NAMED_RE = re.compile(r'([A-Za-z][\w-]*)\s*\((\d+)\)')


def load_cause_names(asn_dir: Path) -> dict:
    """Parse the CDD file. Returns
    {cause_no: {'name': str, 'subs': {sub_no: sub_name}}}.
    Causes whose sub cause type has no named values get an empty 'subs'."""
    text = (Path(asn_dir) / CDD_FILE).read_text(encoding='utf-8', errors='replace')

    sub_types = {m.group(1): {int(n): name for name, n in _NAMED_RE.findall(m.group(2))}
                 for m in _SUBTYPE_RE.finditer(text)}

    names: dict = {}
    choice = _CHOICE_RE.search(text)
    if choice:
        for line in choice.group(1).splitlines():
            m = _ALT_RE.match(line)
            if m:
                name, no, sub_type = m.group(1), int(m.group(2)), m.group(3)
                names[no] = {'name': name, 'subs': sub_types.get(sub_type, {})}
    return names


def event_type_info(cause_code_v2: dict, names: dict) -> tuple:
    """(cause_no, cause_name, sub_no, sub_name | None) for a decoded CauseCodeV2."""
    alt, sub_no = cause_code_v2['ccAndScc']
    m = re.match(r'^(.*?)(\d+)$', alt)
    cause_name, cause_no = (m.group(1), int(m.group(2))) if m else (alt, -1)
    entry = names.get(cause_no)
    sub_name = entry['subs'].get(sub_no) if entry else None
    return cause_no, cause_name, sub_no, sub_name


def describe_event_type(cause_code_v2, names: dict) -> str:
    """'roadworks(3) shortTermStationaryRoadworks(4)' (meaning and code, cause first).

    None (e.g. a termination DENM without situation container) gives
    'n/a (no situation container)'. Sub cause codes without a name in the CDD
    are shown as 'unknown(n)'; causes without named sub causes show 'unnamed(n)'.
    """
    if cause_code_v2 is None:
        return 'n/a (no situation container)'
    cause_no, cause_name, sub_no, sub_name = event_type_info(cause_code_v2, names)
    entry = names.get(cause_no)
    if sub_name:
        sub = sub_name
    elif entry and not entry['subs']:
        sub = 'unnamed'
    else:
        sub = 'unknown'
    return f'{cause_name}({cause_no}) {sub}({sub_no})'


def denm_event_type(denm: dict, names: dict) -> str:
    """Event type text of a decoded DENM (situation.eventType)."""
    situation = denm['denm'].get('situation')
    return describe_event_type(situation['eventType'] if situation else None, names)
