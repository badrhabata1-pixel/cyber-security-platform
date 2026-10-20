// Discovers every module's UI manifest at build/dev time. Modules that have not
// shipped a manifest yet simply do not appear.
//
// This file lives in p4_platform/ui/src/shell/, so the repo root is four levels up.
const found = import.meta.glob('../../../../p*/ui/manifest.js', { eager: true })

function normalize(entry) {
  const m = entry?.default ?? entry?.manifest ?? entry
  return Array.isArray(m) ? m : [m]
}

export const manifests = Object.entries(found)
  .flatMap(([file, mod]) => normalize(mod).map((m) => ({ ...m, file })))
  .filter((m) => m && typeof m.path === 'string' && m.title)
  .map((m) => ({
    path: m.path.startsWith('/') ? m.path : `/${m.path}`,
    title: m.title,
    roles: Array.isArray(m.roles) ? m.roles : [],
    component: m.component ?? null,
    file: m.file,
  }))
  .sort((a, b) => a.title.localeCompare(b.title))

export const manifestsForRole = (role) =>
  manifests.filter((m) => m.roles.length === 0 || m.roles.includes(role))
