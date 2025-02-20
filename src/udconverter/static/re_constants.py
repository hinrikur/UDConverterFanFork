ICE_CHARS = r"A-Za-zþæðöÞÆÐÖáéýúíóÁÉÝÚÍÓ"
LOWER_ICE_CHARS = rf"a-zþæðöáéýúíó"
UPPER_ICE_CHARS = rf"A-ZA-ZÞÆÐÖÞÆÐÖÁÉÝÚÍÓÁÉÝÚÍÓ"
ANY_LOWER_ICE_CHAR = rf"[{LOWER_ICE_CHARS}]"
ANY_UPPER_ICE_CHAR = rf"[{UPPER_ICE_CHARS}]"
ANY_ICE_CHAR = rf"[{ICE_CHARS}]"


ANY_VERB_LABEL = r"(BE|DO|HV|MD|RD|V(A|B))(P|D|N|)(I|S|N|G|)"
ANY_PARTICLE_LABEL = r"(RPX?|Q-.|ADVR?|PRO-.|ONE\+Q-.|OTHER-.|WD-.)"

PARTICLE_NODE = rf"\({ANY_PARTICLE_LABEL} {ANY_ICE_CHAR}+\$-{ANY_ICE_CHAR}+\)"
PARTICLE_MIDDLE_NODE = rf"\({ANY_PARTICLE_LABEL} \${ANY_ICE_CHAR}+\$-{ANY_ICE_CHAR}+\)"
PARTICLE_TOKEN = rf"(?<= ){ANY_ICE_CHAR}+(?=\$)"  # matches
PARTICLE_MIDDLE_TOKEN = rf"(?<= )\${ANY_ICE_CHAR}+(?=\$)"
PARTICLE_START = rf"(?<= )\$(?={ANY_ICE_CHAR})"

VERB_NODE = rf"\({ANY_VERB_LABEL}(-(N|A|D|G))? \${ANY_ICE_CHAR}+-{ANY_ICE_CHAR}+\)"
VERB_START = rf"(?<=[A-Z] )\$(?={ANY_ICE_CHAR})"  # matches '$' in start of verb
VERB_TOKEN = rf"(?<=\$)[{ANY_UPPER_ICE_CHAR}]+(?=-)"
VERB_TAG = rf"(?<=\(){ANY_VERB_LABEL}(-(N|A|D|G))?"
MIDDLE_VERB_NODE = rf"\({ANY_VERB_LABEL}+ \${ANY_ICE_CHAR}+\$-{ANY_ICE_CHAR}+\)"


LEMMA_START_GENERAL = (
    rf"((?<={ANY_LOWER_ICE_CHAR}-)(?={ANY_LOWER_ICE_CHAR}))"  # MATCHES START OF LEMMA
)
LEMMA_TOKEN_GENERAL = rf"(?<=-){ANY_LOWER_ICE_CHAR}+(?=\)\))"
LEMMA_END_GENERAL = rf"(?<={ANY_ICE_CHAR})(?=\))"  # matches end of lemma

MIDDLE_VERB_NODE = rf"\({ANY_VERB_LABEL}+ \${ANY_ICE_CHAR}+\$-{ANY_ICE_CHAR}+\)"

DET_TOKEN = rf"(?<=D-. \$){ANY_LOWER_ICE_CHAR}*(?=[-\)])"  # matches the token of a determiner, excluding "$"
DET_TOKEN_ALT = rf"(?<=D-.-TTT \$){ANY_LOWER_ICE_CHAR}*(?=[-\)])"  # matches det token in case of -TTT in tag
DET_TOKEN_CAPS = rf"(?<=D-. \$){ANY_UPPER_ICE_CHAR}*(?=[-\)])"  # match det token if in caps (few examples)
DET_NODE = rf" ?\(D-[A-Z] \$[{ICE_CHARS}*$-]*\)"  # matches a whole determiner node
# det_node_alt = r'-TTT'
NOUN_TRAIL = r"(?<=)\$(?=[-\)])"  # matches the trailing "$" of a noun
NOUN_NODE = r" {0,1}\(((N|NS|NPR|NPRS)-|FW).*\$-"  # matches a whole noun node
NOUN_TOKEN_INCOMPLETE = (
    r"(?<=N-. )(</?dash/?>)?[^($]*(?=[-\)])"  # noun token where "$" is missing
)


TAGS_22 = rf"\((ADJ|ADJR|ADV|FP|N|NPR|NS|NUM|ONE|Q|VAG|VAN|VBN|VBPI|WPRO)(\+{ANY_ICE_CHAR}+)?22(-[NADG])? [{ICE_CHARS}<>]+-[{ICE_CHARS}]+\)"
TAGS_33 = rf"\((ADJ|ADJR|ADV|FP|N|NPR|NS|NUM|ONE|Q|VAG|VAN|VBN|VBPI|WPRO)(\+{ANY_ICE_CHAR}+)?33(-[NADG])? [{ICE_CHARS}<>]+-[{ICE_CHARS}]+\)"
