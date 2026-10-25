export const ruleTabs = (view: boolean | "sets" = false) =>
  `<nav class="workspace-tabs" aria-label="Rule workspace"><a href="#rules" ${view === false ? 'aria-current="page"' : ""}>Signatures</a><a href="#rule-feeds" ${view === true ? 'aria-current="page"' : ""}>Rule feeds</a><a href="#signature-sets" ${view === "sets" ? 'aria-current="page"' : ""}>Signature sets</a></nav>`;
