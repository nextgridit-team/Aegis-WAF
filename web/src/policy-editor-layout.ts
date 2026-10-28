type Section = {
  id: string;
  title: string;
  description: string;
  nodes: Element[];
};
function organizeSignatureOptions(form: HTMLFormElement) {
  const tuning = form
    .querySelector<HTMLSelectElement>('[name="signature_paranoia"]')!
    .closest("details")!;
  const children = Array.from(tuning.children);
  const body = (
    form.elements.namedItem("signature_body_kib") as HTMLElement
  ).closest("label")!;
  const exclusions = (
    form.elements.namedItem("signature_exclusions") as HTMLElement
  ).closest("label")!;
  const panel = (title: string) => {
    const details = document.createElement("details");
    details.className = "advanced policy-options-panel";
    const summary = document.createElement("summary");
    const text = document.createElement("span");
    text.textContent = title;
    const preview = document.createElement("small");
    summary.append(text, preview);
    details.append(summary);
    return details;
  };
  const inspection = panel("Body and response inspection");
  inspection.dataset.policyInspection = "";
  inspection.append(
    ...children.slice(children.indexOf(body), children.indexOf(exclusions)),
  );
  const exceptions = panel("Signature exceptions");
  exceptions.dataset.policyExceptions = "";
  exceptions.append(
    form.querySelector("[data-policy-browse-signatures]")!,
    form.querySelector("[data-policy-signature-browser]")!,
    ...children.slice(children.indexOf(exclusions)),
  );
  tuning.before(inspection, exceptions);
  const update = () => {
    inspection.querySelector("summary small")!.textContent =
      `Request ${(form.elements.namedItem("signature_body_kib") as HTMLInputElement).value} KiB · responses ${(form.elements.namedItem("signature_response_mode") as HTMLSelectElement).value}`;
    let count = 0;
    try {
      const parsed = JSON.parse(
        (
          form.elements.namedItem(
            "signature_scoped_exclusions",
          ) as HTMLTextAreaElement
        ).value || "[]",
      );
      if (Array.isArray(parsed)) count = parsed.length;
    } catch {
      count = -1;
    }
    exceptions.querySelector("summary small")!.textContent =
      count < 0
        ? "Check exception JSON"
        : `${count} scoped · ${
            String(
              (
                form.elements.namedItem(
                  "signature_exclusions",
                ) as HTMLInputElement
              ).value,
            )
              .split(/[\s,]+/)
              .filter(Boolean).length
          } global exclusions`;
  };
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  update();
}
export function mountPolicyLayout(form: HTMLFormElement) {
  organizeSignatureOptions(form);
  const nodes = Array.from(form.children);
  const index = (text: string) =>
    nodes.findIndex((n) => n.tagName === "H3" && n.textContent === text);
  const network = form
    .querySelector<HTMLSelectElement>('[name="network_geo_mode"]')!
    .closest("details")!;
  const community = form.querySelector<HTMLElement>("[data-community]")!;
  const apps = form.querySelector<HTMLElement>("#policy-assignment-section")!;
  const footer = form.querySelector<HTMLElement>(":scope > .form-actions")!;
  const managed = index("Managed signatures"),
    traffic = index("Shared protection"),
    rules = index("Rule groups");
  const sections: Section[] = [
    {
      id: "basics",
      title: "Policy basics",
      description:
        "Name the policy and decide how it handles matching traffic.",
      nodes: nodes.slice(0, nodes.indexOf(network)),
    },
    {
      id: "signatures",
      title: "Signature protection",
      description:
        "Choose a detection set and its sensitivity. Start in Observe while tuning.",
      nodes: nodes.slice(managed + 1, traffic),
    },
    {
      id: "traffic",
      title: "Bot & flood protection",
      description:
        "Control request volume and challenge suspicious browser traffic.",
      nodes: nodes.slice(traffic + 1, rules),
    },
    {
      id: "access",
      title: "Access & location",
      description:
        "Use trusted address objects, client ranges and country restrictions.",
      nodes: [network],
    },
    {
      id: "rules",
      title: "Targeted rules",
      description:
        "Choose community mitigations and optional application-specific rule groups.",
      nodes: [community, ...nodes.slice(rules, nodes.indexOf(apps))],
    },
    {
      id: "applications",
      title: "Application assignments",
      description:
        "Choose where this policy runs and which clients it applies to.",
      nodes: [apps],
    },
  ];
  const summary = document.createElement("div");
  summary.className = "policy-live-summary";
  summary.setAttribute("aria-label", "Policy preview");
  summary.innerHTML =
    '<span class="policy-preview-mode" data-preview-mode></span><span data-preview-protection></span><span data-preview-applications></span>';
  const workspace = document.createElement("div");
  workspace.className = "policy-editor-workspace";
  const nav = document.createElement("nav");
  nav.className = "policy-editor-nav";
  nav.setAttribute("aria-label", "Policy sections");
  const body = document.createElement("div");
  body.className = "policy-editor-content";
  const jump = (id: string) => {
    const section = body.querySelector<HTMLElement>(`#policy-section-${id}`)!;
    if (id === "access") network.open = true;
    section.scrollIntoView({ block: "start", behavior: "instant" });
    section.focus({ preventScroll: true });
    nav.querySelectorAll("button").forEach((button) => {
      button.setAttribute(
        "aria-current",
        String(button.dataset.policyJump === id),
      );
    });
  };
  for (const [i, s] of sections.entries()) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.policyJump = s.id;
    button.innerHTML = `<span aria-hidden="true">${String(i + 1).padStart(2, "0")}</span>${s.title}`;
    button.setAttribute("aria-controls", `policy-section-${s.id}`);
    button.setAttribute("aria-current", String(i === 0));
    button.addEventListener("click", () => jump(s.id));
    nav.append(button);
    const section = document.createElement("section");
    section.id = `policy-section-${s.id}`;
    section.className = "policy-editor-section";
    section.tabIndex = -1;
    section.setAttribute("aria-labelledby", `policy-title-${s.id}`);
    section.innerHTML = `<header class="policy-section-heading"><span aria-hidden="true">${String(i + 1).padStart(2, "0")}</span><div><h3 id="policy-title-${s.id}">${s.title}</h3><p>${s.description}</p></div></header>`;
    section.append(...s.nodes);
    body.append(section);
  }
  apps.querySelector(":scope > h3")?.remove();
  workspace.append(nav, body);
  form.replaceChildren(summary, workspace, footer);
  footer.classList.add("policy-save-bar");
  const draft = document.createElement("small");
  draft.dataset.policyDraft = "";
  draft.textContent = "Changes apply only when you save.";
  footer.prepend(draft);
  const mode = () =>
    String((form.elements.namedItem("mode") as HTMLSelectElement).value);
  const check = (name: string) =>
    (form.elements.namedItem(name) as HTMLInputElement).checked;
  const update = () => {
    const current = mode();
    summary.dataset.mode = current;
    summary.querySelector<HTMLElement>("[data-preview-mode]")!.textContent =
      current === "off"
        ? "Off · policy protection paused"
        : current === "observe"
          ? "Observe · evaluate and allow"
          : "Block · honor configured actions";
    const signature = (
      form.elements.namedItem("signature_mode") as HTMLSelectElement
    ).value;
    summary.querySelector<HTMLElement>(
      "[data-preview-protection]",
    )!.textContent =
      current === "off"
        ? "Settings below are kept for later."
        : `Signatures: ${signature}${current === "observe" && signature === "block" ? " (capped to Observe)" : ""} · flood ${check("flood_enabled") ? "on" : "off"} · anti-bot ${check("bot_enabled") ? "on" : "off"}`;
    const count = form.querySelectorAll("[data-policy-assignment]").length;
    summary.querySelector<HTMLElement>(
      "[data-preview-applications]",
    )!.textContent = `${count} application${count === 1 ? "" : "s"} assigned`;
  };
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  const observer = new MutationObserver(update);
  observer.observe(form.querySelector("#policy-assignments")!, {
    childList: true,
  });
  const dialog = form.closest("dialog")!;
  const scrollLife = new AbortController();
  let frame = 0;
  dialog.addEventListener(
    "scroll",
    () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        if (!form.isConnected) {
          scrollLife.abort();
          return;
        }
        let current = sections[0].id;
        const atBottom =
          dialog.scrollTop + dialog.clientHeight >= dialog.scrollHeight - 4;
        if (atBottom) current = sections[sections.length - 1].id;
        else
          for (const section of sections) {
            if (
              body
                .querySelector<HTMLElement>(`#policy-section-${section.id}`)!
                .getBoundingClientRect().top <=
              dialog.getBoundingClientRect().top + 160
            )
              current = section.id;
          }
        nav
          .querySelectorAll<HTMLButtonElement>("button")
          .forEach((button) =>
            button.setAttribute(
              "aria-current",
              String(button.dataset.policyJump === current),
            ),
          );
      });
    },
    { passive: true, signal: scrollLife.signal },
  );
  dialog.addEventListener(
    "close",
    () => {
      scrollLife.abort();
      if (frame) cancelAnimationFrame(frame);
    },
    { once: true },
  );

  dialog.addEventListener("close", () => observer.disconnect(), { once: true });
  // Reveal collapsed settings before the browser focuses an invalid control.
  form.addEventListener(
    "invalid",
    (event) => {
      const field = event.target as HTMLElement;
      let parent = field.parentElement;
      while (parent && parent !== form) {
        if (parent instanceof HTMLDetailsElement) parent.open = true;
        if (parent.hidden) parent.hidden = false;
        parent = parent.parentElement;
      }
    },
    true,
  );
  update();
  return { jump, update };
}
