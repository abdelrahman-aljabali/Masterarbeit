/**
 * ─── ESPR product-category taxonomy ───────────────────────────────────────────
 *
 * Canonical reference data — part of the ESPR domain model, like the field
 * catalog. Lives in the shared kernel so the frontend (category picker) and the
 * backend (category validation) read the SAME tree. Selecting a leaf yields a
 * path string like "Fashion & Apparel > Clothing > Dresses & Tops" plus the
 * applicable delegated act (inherited from the nearest ancestor that sets one).
 */
import type { Sector } from "./engine/types.js";

export interface TaxNode {
  id: string;
  label: string;
  delegatedAct?: string;
  /** The field-schema sector this branch maps to. Set on a root; inherited by
   *  descendants. A category whose sector has no loaded schema (or no sector at
   *  all, e.g. construction/tyres) is "not yet supported" — see the registry. */
  sector?: Sector;
  children?: TaxNode[];
}

export const DPP_TAXONOMY: TaxNode[] = [
  {
    id: "fashion", label: "Fashion & Apparel", sector: "textile",
    delegatedAct: "ESPR Textiles Delegated Act (expected 2027)",
    children: [
      { id: "fashion-clothing", label: "Clothing", children: [
        { id: "fc-tops", label: "Dresses & Tops" },
        { id: "fc-trousers", label: "Trousers & Jeans" },
        { id: "fc-outerwear", label: "Outerwear & Jackets" },
        { id: "fc-knitwear", label: "Knitwear & Sweaters" },
        { id: "fc-underwear", label: "Underwear & Lingerie" },
        { id: "fc-activewear", label: "Activewear & Sportswear" },
      ]},
      { id: "fashion-footwear", label: "Footwear", children: [
        { id: "ff-sneakers", label: "Sneakers & Trainers" },
        { id: "ff-boots", label: "Boots" },
        { id: "ff-formal", label: "Formal Shoes" },
      ]},
      { id: "fashion-accessories", label: "Accessories", children: [
        { id: "fa-bags", label: "Bags & Handbags" },
        { id: "fa-scarves", label: "Scarves & Wraps" },
        { id: "fa-hats", label: "Hats & Caps" },
      ]},
      { id: "fashion-home", label: "Home Textiles", children: [
        { id: "fh-bedding", label: "Bedding & Linen" },
        { id: "fh-towels", label: "Towels" },
      ]},
    ],
  },
  {
    id: "batteries", label: "Batteries", sector: "battery",
    delegatedAct: "EU Battery Regulation 2023/1542 (DPP from Feb 2027)",
    children: [
      { id: "bat-ev", label: "EV Traction Batteries" },
      { id: "bat-industrial", label: "Industrial Batteries" },
      { id: "bat-portable", label: "Portable Batteries" },
    ],
  },
  {
    id: "electronics", label: "Electronics", sector: "electronics",
    delegatedAct: "ESPR Electronics Delegated Act (planned)",
    children: [
      { id: "el-phones", label: "Smartphones" },
      { id: "el-computers", label: "Laptops & Computers" },
      { id: "el-appliances", label: "Home Appliances" },
    ],
  },
  {
    id: "furniture", label: "Furniture", sector: "furniture",
    delegatedAct: "ESPR Furniture Delegated Act (planned)",
    children: [
      { id: "fu-seating", label: "Seating" },
      { id: "fu-tables", label: "Tables & Desks" },
      { id: "fu-storage", label: "Storage & Wardrobes" },
    ],
  },
  {
    id: "construction", label: "Construction Products",
    delegatedAct: "CPR + ESPR (planned)",
    children: [
      { id: "con-structural", label: "Structural Elements" },
      { id: "con-insulation", label: "Insulation" },
      { id: "con-flooring", label: "Flooring" },
    ],
  },
  {
    id: "tyres", label: "Tyres",
    delegatedAct: "ESPR Tyres Delegated Act (planned)",
    children: [
      { id: "ty-passenger", label: "Passenger Car" },
      { id: "ty-truck", label: "Truck & Bus" },
    ],
  },
];

export interface FlatCategory { id: string; path: string; delegatedAct: string; sector?: Sector }

/** Flatten the tree to { id, path, delegatedAct, sector } for search + validation. */
export function flattenTaxonomy(nodes: TaxNode[] = DPP_TAXONOMY, path: string[] = [], act = "", sector?: Sector): FlatCategory[] {
  const out: FlatCategory[] = [];
  for (const node of nodes) {
    const currentPath = [...path, node.label];
    const currentAct = node.delegatedAct ?? act;
    const currentSector = node.sector ?? sector;
    out.push({ id: node.id, path: currentPath.join(" > "), delegatedAct: currentAct, sector: currentSector });
    if (node.children) out.push(...flattenTaxonomy(node.children, currentPath, currentAct, currentSector));
  }
  return out;
}

const PATHS = new Set(flattenTaxonomy().map((c) => c.path));

/** Whether a category path exists in the taxonomy (used by the backend gate). */
export function isKnownCategory(path: string): boolean {
  return PATHS.has(path);
}

/** Delegated act for a category path, if any. */
export function delegatedActFor(path: string): string | undefined {
  return flattenTaxonomy().find((c) => c.path === path)?.delegatedAct;
}

/** The field-schema sector a category path belongs to (undefined for branches
 *  with no sector yet, e.g. construction/tyres). */
export function sectorForCategory(path: string): Sector | undefined {
  return flattenTaxonomy().find((c) => c.path === path)?.sector;
}
