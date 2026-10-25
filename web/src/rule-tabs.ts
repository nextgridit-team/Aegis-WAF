export const ruleTabs = (feeds = false) =>
  `<nav class="workspace-tabs" aria-label="Rule workspace"><a href="#rules" ${!feeds ? 'aria-current="page"' : ""}>Signatures</a><a href="#rule-feeds" ${feeds ? 'aria-current="page"' : ""}>Rule feeds</a></nav>`;
