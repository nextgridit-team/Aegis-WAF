type ScaleOptions = {
  unit: string;
  log?: boolean;
  low: string;
  high: string;
  step?: string;
};
const scales: Record<string, ScaleOptions> = {
  requests_per_second: {
    unit: "req/s per client",
    log: true,
    low: "Fewer requests",
    high: "More requests",
  },
  burst: {
    unit: "requests in a client burst",
    log: true,
    low: "Smaller bursts",
    high: "Larger bursts",
  },
  site_requests_per_second: {
    unit: "req/s per application",
    log: true,
    low: "Fewer requests",
    high: "More requests",
  },
  site_burst: {
    unit: "requests in an application burst",
    log: true,
    low: "Smaller bursts",
    high: "Larger bursts",
  },
  bot_score_threshold: {
    unit: "/ 100 suspicion score",
    low: "Challenge earlier",
    high: "Require stronger signals",
  },
  bot_clearance_minutes: {
    unit: "minutes",
    low: "Shorter clearance",
    high: "Longer clearance",
  },
  bot_risk_rate: {
    unit: "req/s signal threshold",
    log: true,
    low: "More sensitive",
    high: "Less sensitive",
  },
  bot_risk_burst: {
    unit: "requests in a signal burst",
    log: true,
    low: "Smaller bursts",
    high: "Larger bursts",
  },
  signature_body_kib: {
    unit: "KiB inspected",
    low: "Smaller prefix",
    high: "Larger prefix",
    step: "any",
  },
  signature_response_body_kib: {
    unit: "KiB inspected",
    low: "Smaller prefix",
    high: "Larger prefix",
    step: "any",
  },
  signature_threshold: {
    unit: "inbound anomaly score",
    low: "Block at lower scores",
    high: "Require higher scores",
  },
  signature_outbound_threshold: {
    unit: "outbound anomaly score",
    low: "Block at lower scores",
    high: "Require higher scores",
  },
};
export function enhanceScale(input: HTMLInputElement, settings: ScaleOptions) {
  if (input.dataset.scaleReady) return;
  input.dataset.scaleReady = "true";
  if (settings.step) input.step = settings.step;
  const label = input.closest("label")!;
  label.classList.add("policy-scale");
  const title =
    label.firstChild?.textContent?.trim() ||
    input.getAttribute("aria-label") ||
    "Limit";
  const row = document.createElement("div");
  row.className = "policy-scale-value";
  const output = document.createElement("output");
  output.setAttribute("aria-live", "off");
  const exact = document.createElement("span");
  exact.className = "policy-exact-value";
  input.setAttribute("aria-label", title);
  exact.append(input);
  row.append(output, exact);
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "0";
  slider.max = settings.log ? "1000" : input.max;
  slider.min = settings.log ? "0" : input.min;
  slider.step = "1";
  slider.setAttribute("aria-label", title + " scale");
  slider.dataset.scaleFor = input.name || "assignment_priority";
  const ends = document.createElement("div");
  ends.className = "policy-scale-ends";
  const lo = document.createElement("span"),
    hi = document.createElement("span");
  lo.textContent = settings.low;
  hi.textContent = settings.high;
  ends.append(lo, hi);
  const min = Number(input.min) || 0,
    max = Number(input.max) || 100;
  const position = (v: number) =>
    settings.log
      ? Math.log(Math.max(min, v) / min) / Math.log(max / min)
      : (v - min) / (max - min);
  const value = (p: number) =>
    settings.log
      ? Math.round(min * Math.pow(max / min, p))
      : Math.round(min + (max - min) * p);
  const update = () => {
    const v = Number(input.value);
    const valid =
      input.value !== "" && Number.isFinite(v) && v >= min && v <= max;
    if (valid)
      slider.value = settings.log
        ? String(Math.round(position(v) * 1000))
        : String(v);
    slider.dataset.exact = String(valid);
    slider.setAttribute(
      "aria-valuetext",
      valid
        ? `${input.value} ${settings.unit}`
        : "Enter an exact value within the allowed range",
    );
    output.textContent = valid
      ? `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 }).format(v)} ${settings.unit}`
      : "Enter a valid value";
  };
  slider.addEventListener("input", () => {
    input.value = String(
      settings.log ? value(Number(slider.value) / 1000) : Number(slider.value),
    );
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
  if (settings.log)
    slider.addEventListener("keydown", (event) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (
        ![
          "ArrowLeft",
          "ArrowRight",
          "ArrowUp",
          "ArrowDown",
          "Home",
          "End",
          "PageUp",
          "PageDown",
        ].includes(event.key)
      )
        return;
      event.preventDefault();
      const current = Number(input.value) || min;
      const step = Math.max(
        1,
        Math.round(
          current * (["PageUp", "PageDown"].includes(event.key) ? 0.2 : 0.05),
        ),
      );
      const next =
        event.key === "Home"
          ? min
          : event.key === "End"
            ? max
            : Math.max(
                min,
                Math.min(
                  max,
                  current +
                    (["ArrowRight", "ArrowUp", "PageUp"].includes(event.key)
                      ? step
                      : -step),
                ),
              );
      input.value = String(next);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  input.addEventListener("input", update);
  input.addEventListener("change", update);
  label.append(row, slider, ends);
  update();
}
function enhanceChoice(select: HTMLSelectElement) {
  if (select.dataset.choiceReady) return;
  select.dataset.choiceReady = "true";
  const label =
    select.getAttribute("aria-label") ||
    document.querySelector<HTMLLabelElement>(`label[for="${select.id}"]`)
      ?.textContent ||
    select.closest("label")?.firstChild?.textContent ||
    "Protection mode";
  const group = document.createElement("div");
  group.className = "policy-mode-options";
  group.setAttribute("role", "radiogroup");
  group.setAttribute("aria-label", label.trim());
  const hints =
    select.name === "mode"
      ? {
          off: "Keep settings, pause protection",
          observe: "Evaluate matches and allow traffic",
          block: "Honor configured rule actions",
        }
      : undefined;
  const buttons = Array.from(select.options).map((option) => {
    const button = document.createElement("button");
    button.type = "button";
    button.role = "radio";
    button.dataset.choiceValue = option.value;
    const [name, ...description] = option.textContent!.split(" · ");
    const title = document.createElement("strong"),
      help = document.createElement("small");
    title.textContent = name;
    help.textContent =
      hints?.[option.value as keyof typeof hints] || description.join(" · ");
    button.append(title, help);
    button.addEventListener("click", () => {
      if (select.disabled) return;
      select.value = option.value;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    group.append(button);
    return button;
  });
  const update = () =>
    buttons.forEach((button) => {
      const selected = button.dataset.choiceValue === select.value;
      button.setAttribute("aria-checked", String(selected));
      button.tabIndex = selected ? 0 : -1;
      button.disabled = select.disabled;
    });
  group.addEventListener("keydown", (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    if (
      ![
        "ArrowLeft",
        "ArrowRight",
        "ArrowUp",
        "ArrowDown",
        "Home",
        "End",
      ].includes(event.key)
    )
      return;
    event.preventDefault();
    const index = buttons.findIndex(
      (button) => button.dataset.choiceValue === select.value,
    );
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? buttons.length - 1
          : (index +
              (["ArrowRight", "ArrowDown"].includes(event.key)
                ? 1
                : buttons.length - 1)) %
            buttons.length;
    buttons[next].click();
    buttons[next].focus();
  });
  (select.closest("label") || select).after(group);
  select.classList.add("policy-native-choice");
  select.setAttribute("aria-hidden", "true");
  select.tabIndex = -1;
  const oldLabel = select.id
    ? document.querySelector<HTMLLabelElement>(`label[for="${select.id}"]`)
    : null;
  if (oldLabel) oldLabel.classList.add("policy-choice-label");
  select.addEventListener("change", update);
  const observer = new MutationObserver(update);
  observer.observe(select, { attributes: true, attributeFilter: ["disabled"] });
  select
    .closest("dialog")
    ?.addEventListener("close", () => observer.disconnect(), { once: true });
  update();
}
export function mountPolicyControls(form: HTMLFormElement) {
  for (const [name, settings] of Object.entries(scales)) {
    const input = form.elements.namedItem(name);
    if (input instanceof HTMLInputElement) enhanceScale(input, settings);
  }
  for (const name of [
    "mode",
    "signature_mode",
    "signature_response_mode",
    "network_geo_mode",
    "network_allow_scope",
    "network_geo_strategy",
    "network_unknown_country",
  ]) {
    const select = form.elements.namedItem(name);
    if (select instanceof HTMLSelectElement) enhanceChoice(select);
  }
  for (const name of [
    "flood_enabled",
    "bot_enabled",
    "community_enabled",
    "bot_challenge_enabled",
    "block_empty_user_agent",
  ]) {
    const input = form.elements.namedItem(name) as HTMLInputElement;
    input.setAttribute("role", "switch");
    input.closest("label")?.classList.add("policy-feature-switch");
  }
  for (const [rate, burst] of [
    ["requests_per_second", "burst"],
    ["site_requests_per_second", "site_burst"],
    ["bot_risk_rate", "bot_risk_burst"],
  ]) {
    const rateInput = form.elements.namedItem(rate) as HTMLInputElement,
      burstInput = form.elements.namedItem(burst) as HTMLInputElement;
    const note = document.createElement("small");
    note.className = "policy-limit-note";
    note.setAttribute("aria-live", "polite");
    burstInput.closest("label")!.append(note);
    const update = () => {
      const bad = Number(burstInput.value) < Number(rateInput.value);
      const message = bad
        ? `Burst must allow at least ${rateInput.value} requests. Increase burst or lower the rate.`
        : "Burst allows a short spike above the sustained rate.";
      burstInput.setCustomValidity(bad ? message : "");
      burstInput.setAttribute("aria-invalid", String(bad));
      note.textContent = message;
      note.classList.toggle("error-text", bad);
    };
    rateInput.addEventListener("input", update);
    burstInput.addEventListener("input", update);
    update();
  }
  const flood = form.elements.namedItem("flood_enabled") as HTMLInputElement;
  const floodControls = (
    form.elements.namedItem("requests_per_second") as HTMLElement
  ).closest(".form-grid") as HTMLElement;
  floodControls.dataset.policyFlood = "";
  const floodNote = document.createElement("p");
  floodNote.className = "policy-feature-note";
  floodNote.textContent = "Flood limits are saved while this control is off.";
  floodControls.before(floodNote);
  const updateFlood = () => {
    floodControls.hidden = !flood.checked;
    floodNote.hidden = flood.checked;
  };
  flood.addEventListener("change", updateFlood);
  updateFlood();
  const bot = form.elements.namedItem("bot_enabled") as HTMLInputElement;
  const botSettings = (
    form.elements.namedItem("bot_challenge_enabled") as HTMLElement
  ).closest("details")!;
  const botUpdate = () => {
    botSettings.classList.toggle("policy-control-idle", !bot.checked);
  };
  bot.addEventListener("change", botUpdate);
  botUpdate();
  return {
    enhanceAssignment: (root: HTMLElement) => {
      const input = root.querySelector<HTMLInputElement>(
        "[data-assignment-priority]",
      );
      if (input)
        enhanceScale(input, {
          unit: "priority · lower matches first",
          low: "Earlier",
          high: "Later",
        });
    },
  };
}
