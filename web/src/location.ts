export type LocalLocation = {
  location_source?: string;
  location_reference_ip?: string;
  observed_country?: string;
};
export function localLocationNote(event: LocalLocation) {
  if (event.location_source === "local_reference")
    return "Local network · assigned from " + event.location_reference_ip;
  if (event.location_source === "local_unlocated")
    return event.location_reference_ip
      ? "Local network · Geo data unavailable for reference IP"
      : "Local network · public IP reference not configured";
  return "";
}
