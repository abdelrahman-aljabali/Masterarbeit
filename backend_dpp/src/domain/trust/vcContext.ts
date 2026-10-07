import { CONTEXT_URL, CONTEXT_URL_V2, CONTEXT_URL_V3, VOCAB_URL, VOCAB_UNREGISTERED_URL } from "./trustUrls.js";
import { DPP_FIELDS } from "../../dpp-core/index.js";
import { contexts as credentialsContexts } from "@digitalbazaar/credentials-context";

/**
 * ─── TrustDPP JSON-LD context (semantic layer) ────────────────────────────────
 * Served at a stable URL and referenced from every credential's `@context`
 * alongside credentials/v2. `@vocab` maps every DPP-domain term (composition,
 * environmental, manufacturing, …) into the TrustDPP vocabulary namespace, so
 * RDF canonicalization (eddsa-rdfc-2022) processes the full credentialSubject
 * without dropping terms — and without hand-enumerating the ~85-field catalog.
 */

export const DPP_CONTEXT_PATH = "/contexts/dpp-v1.jsonld";
export const DPP_CONTEXT_PATH_V2 = "/contexts/dpp-v2.jsonld";
export const DPP_CONTEXT_PATH_V3 = "/contexts/dpp-v3.jsonld";
export const VOCAB_PATH = "/vocab";

/** The PINNED, environment-independent context URL frozen into signed bytes.
 *  (The context is still SERVED at its path on whatever host runs the app —
 *  the identifier and the serving host are deliberately decoupled.)
 *  New credentials reference v3 (explicit terms); v1/v2 stay served forever. */
export const dppContextUrl = () => CONTEXT_URL_V3;

export const DPP_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "@vocab": "https://trustdpp.co/vocab#",
    DppTierCredential: "https://trustdpp.co/vocab#DppTierCredential",
  },
} as const;

const VOCAB = "https://trustdpp.co/vocab#";
const listTerm = (name: string) => ({ "@id": `${VOCAB}${name}`, "@container": "@list" as const });

export const DPP_CONTEXT_V2 = {
  "@context": {
    "@version": 1.1,
    "@vocab": VOCAB,
    DppTierCredential: `${VOCAB}DppTierCredential`,
    // Order-significant arrays (one per array-typed catalog field): @list keeps
    // their sequence inside the signed RDF — composition order, route order,
    // layer order and certificate order are all meaningful data.
    fibers: listTerm("fibers"),                 // composition.fibers
    items: listTerm("items"),                   // substances.items
    legs: listTerm("legs"),                     // transport.legs
    programmes: listTerm("programmes"),         // circularity.programmes
    layers: listTerm("layers"),                 // packaging.layers
    certifications: listTerm("certifications"), // certifications
  },
} as const;

// ─── Context v3 — explicit, catalog-generated term definitions (H1) ──────────

const XSD_DATE = "http://www.w3.org/2001/XMLSchema#date";

/** Terms the VCDM 2.0 core context already defines (and protects). */
const CORE_V2_TERMS: ReadonlySet<string> = new Set(
  Object.keys(
    ((credentialsContexts.get("https://www.w3.org/ns/credentials/v2") as
      | { "@context"?: Record<string, unknown> }
      | undefined)?.["@context"]) ?? {},
  ),
);

/** Object-array ENTRY keys — row shapes the catalog cannot express per-key
 *  (an array field is ONE spec). Curated here, next to the generator, so a new
 *  entry key is one line away from being a defined term. */
const ENTRY_TERMS: readonly string[] = [
  // transport.legs
  "from", "to", "mode", "distanceKm", "weightKg", "company",
  // packaging.layers
  "materialType", "weightGrams", "recyclabilityGrade", "recycledContentPct",
  "disposalInstructions", "materialCode", "reusable", "compostable", "selectedSymbols",
  // composition.fibers ("label" caught by the quarantine guard on first run —
  // the tripwire this curated list exists for)
  "pct", "label",
  // substances.items ("name" is core-defined → expands via schema.org/name)
  "cas", "hazard", "location", "concentration", "exemption",
  // certifications (UNTP conformity-claim shape)
  "scheme", "number", "scope", "certifier", "expiryDate", "evidenceUrl", "certifierDid",
];

/** Non-catalog terms the assembler itself writes into subjects. */
const ASSEMBLER_TERMS: readonly string[] = ["role"];

/** Entry-level terms that are calendar dates. */
const ENTRY_DATE_TERMS: ReadonlySet<string> = new Set(["expiryDate", "date"]);

/** Order-significant array terms (carried from v2 — the multiset-signing fix). */
const LIST_TERMS: ReadonlySet<string> = new Set(["fibers", "items", "legs", "programmes", "layers", "certifications"]);

function buildContextV3(): { "@context": Record<string, unknown> } {
  const intermediates = new Set<string>();
  const terminalTypes = new Map<string, Set<string>>();
  for (const f of DPP_FIELDS) {
    const segs = f.vcPath.split(".");
    segs.forEach((seg, i) => {
      if (i < segs.length - 1) {
        intermediates.add(seg);
      } else {
        if (!terminalTypes.has(seg)) terminalTypes.set(seg, new Set());
        terminalTypes.get(seg)!.add(f.type);
      }
    });
  }

  const names = [...new Set([
    ...intermediates,
    ...terminalTypes.keys(),
    ...ENTRY_TERMS,
    ...ASSEMBLER_TERMS,
  ])]
    .filter((n) => n !== "id" && n !== "type" && !CORE_V2_TERMS.has(n))
    .sort();

  const terms: Record<string, unknown> = {};
  for (const name of names) {
    const def: Record<string, unknown> = { "@id": `${VOCAB_URL}${name}` };
    // xsd:date only when EVERY owner of the name is date-typed and the name is
    // never an object node — a term can't be a typed literal in one place and
    // a node property in another without corrupting one of them.
    const types = terminalTypes.get(name);
    const catalogDate = !!types && types.size === 1 && types.has("date") && !intermediates.has(name);
    const entryDate = ENTRY_DATE_TERMS.has(name) && !intermediates.has(name) && !types;
    if (catalogDate || entryDate) def["@type"] = XSD_DATE;
    if (LIST_TERMS.has(name)) def["@container"] = "@list";
    terms[name] = def;
  }

  return {
    "@context": {
      "@version": 1.1,
      "@protected": true,
      "@vocab": VOCAB_UNREGISTERED_URL,
      DppTierCredential: `${VOCAB_URL}DppTierCredential`,
      ...terms,
    },
  };
}

export const DPP_CONTEXT_V3 = buildContextV3();

/**
 * The dereferenceable vocabulary document served at /vocab — the human/machine
 * dictionary behind every term IRI. Labels and regulatory references come from
 * the catalog, so the vocabulary documents ITSELF from the same source of truth.
 */
export function vocabDictionary(): {
  "@vocab": string;
  generatedFrom: string;
  terms: { term: string; iri: string; datatype?: string; container?: string; definedBy: string[] }[];
} {
  const ctx = (DPP_CONTEXT_V3["@context"]) as Record<string, unknown>;
  const byTerminal = new Map<string, string[]>();
  for (const f of DPP_FIELDS) {
    const seg = f.vcPath.split(".").pop()!;
    (byTerminal.get(seg) ?? byTerminal.set(seg, []).get(seg)!).push(`${f.label} (${f.regRef})`);
  }
  const terms = Object.entries(ctx)
    .filter(([k, v]) => !k.startsWith("@") && typeof v === "object" && v !== null)
    .map(([term, def]) => {
      const d = def as Record<string, string>;
      return {
        term,
        iri: d["@id"],
        ...(d["@type"] ? { datatype: d["@type"] } : {}),
        ...(d["@container"] ? { container: d["@container"] } : {}),
        definedBy: byTerminal.get(term) ?? ["structural term (object grouping or array-entry key)"],
      };
    });
  return { "@vocab": VOCAB_URL, generatedFrom: "dpp-core field catalog", terms };
}

/** URL → context body, for the offline document loader: every URL ever minted
 *  into signed bytes must keep resolving to the EXACT body it was signed with. */
export const CONTEXT_BODIES = new Map<string, unknown>([
  [CONTEXT_URL, DPP_CONTEXT],
  [CONTEXT_URL_V2, DPP_CONTEXT_V2],
  [CONTEXT_URL_V3, DPP_CONTEXT_V3],
]);
