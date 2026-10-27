// A form macro only: policy JSON continues to store the three existing fields.
export const sensitivityPresets = [
  {
    name: "Relaxed",
    paranoia: 1,
    inbound: 10,
    outbound: 10,
    hint: "Fewer blocks; subtle attacks may not reach the threshold.",
  },
  {
    name: "Standard",
    paranoia: 1,
    inbound: 5,
    outbound: 4,
    hint: "Occasional tuning; recommended starting point in Observe.",
  },
  {
    name: "Elevated",
    paranoia: 2,
    inbound: 5,
    outbound: 4,
    hint: "More sensitive patterns; review false positives before enforcing.",
  },
  {
    name: "Aggressive",
    paranoia: 3,
    inbound: 3,
    outbound: 3,
    hint: "High false-positive risk; legitimate traffic may be blocked.",
  },
  {
    name: "Maximum",
    paranoia: 4,
    inbound: 2,
    outbound: 2,
    hint: "Expect legitimate traffic to be blocked without careful tuning.",
  },
];
export function sensitivityMarkup() {
  return `<section class="signature-sensitivity"><label class="field" for="signature-sensitivity">Sensitivity <output for="signature-sensitivity" data-sensitivity-label></output></label><input id="signature-sensitivity" aria-label="Signature sensitivity" type="range" min="1" max="5" step="1" value="2"><div class="sensitivity-scale"><span>1 · Relaxed</span><span>2 · Standard</span><span>3 · Elevated</span><span>4 · Aggressive</span><span>5 · Maximum</span></div><p data-sensitivity-hint role="status"></p><small data-sensitivity-values></small><small>Sensitivity adjusts matching strictness and score thresholds, not a performance budget. Choose a lean curated set to reduce the rules evaluated.</small></section>`;
}
export function mountSensitivity(form: HTMLFormElement) {
  const slider = form.querySelector<HTMLInputElement>(
    "#signature-sensitivity",
  )!;
  const fields = [
    "signature_paranoia",
    "signature_threshold",
    "signature_outbound_threshold",
  ].map(
    (name) =>
      form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement,
  );
  const label = form.querySelector<HTMLOutputElement>(
    "[data-sensitivity-label]",
  )!;
  const hint = form.querySelector<HTMLElement>("[data-sensitivity-hint]")!;
  const values = form.querySelector<HTMLElement>("[data-sensitivity-values]")!;
  const update = () => {
    const [paranoia, inbound, outbound] = fields.map((field) =>
      Number(field.value),
    );
    const index = sensitivityPresets.findIndex(
      (p) =>
        p.paranoia === paranoia &&
        p.inbound === inbound &&
        p.outbound === outbound,
    );
    label.value =
      index < 0 ? "Custom" : `${index + 1} · ${sensitivityPresets[index].name}`;
    slider.setAttribute(
      "aria-valuetext",
      index < 0 ? "Custom settings; move to choose a preset" : label.value,
    );
    slider.dataset.custom = String(index < 0);
    if (index >= 0) slider.value = String(index + 1);
    hint.textContent =
      index < 0
        ? "Custom — advanced values do not match a preset. Move the slider to replace all three values."
        : sensitivityPresets[index].hint;
    hint.classList.toggle("error-text", index >= 3);
    values.textContent = `Paranoia ${paranoia} · inbound threshold ${inbound} · outbound threshold ${outbound}`;
  };
  const applyPreset = () => {
    const p = sensitivityPresets[Number(slider.value) - 1];
    [p.paranoia, p.inbound, p.outbound].forEach(
      (value, index) => (fields[index].value = String(value)),
    );
    for (const field of fields)
      field.dispatchEvent(new Event("input", { bubbles: true }));
    update();
  };
  slider.addEventListener("input", applyPreset);
  slider.addEventListener("change", applyPreset);
  for (const field of fields) {
    field.addEventListener("input", update);
    field.addEventListener("change", update);
  }
  update();
}
