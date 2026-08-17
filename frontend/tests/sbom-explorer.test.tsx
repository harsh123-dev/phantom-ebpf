import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PhantomGatewayClient } from "../src/api/gatewayClient";
import { SBOMVerifyPanel } from "../src/features/sbom/components/SBOMVerifyPanel";
import { filterComponents, type CycloneDxComponent } from "../src/features/sbom/sbomUtils";
import type { SbomDetailResponse, SbomVerificationResponse } from "../src/types/phantom";

const client = new PhantomGatewayClient("", () => "token");

const detail: SbomDetailResponse = {
  record: {
    sbom_id: "11111111-1111-4111-8111-111111111111",
    image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sbom_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    format: "CycloneDX",
    spec_version: "1.5",
    component_count: 2,
    verification_status: "pending",
    created_at: "2026-07-24T12:00:00.000Z",
  },
  cyclonedx_document: {
    components: [
      { name: "openssl", version: "3.3.1", purl: "pkg:apk/alpine/openssl@3.3.1", type: "library" },
      { name: "curl", version: "8.8.0", purl: "pkg:apk/alpine/curl@8.8.0", type: "library" },
    ],
  },
  purl_count: 2,
  signature_bundle_uri: null,
  verified_at: null,
  verification_error: null,
};

const runningVerification: SbomVerificationResponse = {
  verification_job_id: "22222222-2222-4222-8222-222222222222",
  sbom_id: detail.record.sbom_id,
  status: "running",
  signing_identity: null,
  issuer: null,
  rekor_entry_uuid: null,
  verified_at: null,
  failure_reason: null,
};

describe("SBOM explorer", () => {
  it("Verify Now button disabled while verification is running", () => {
    const html = renderToStaticMarkup(<SBOMVerifyPanel client={client} detail={detail} initialVerification={runningVerification} />);
    expect(html).toContain("Verification is running.");
    expect(html).toContain("disabled");
  });

  it("ComponentTable filters correctly on search input", () => {
    const components: CycloneDxComponent[] = [
      { name: "openssl", version: "3.3.1", purl: "pkg:apk/alpine/openssl@3.3.1", type: "library" },
      { name: "curl", version: "8.8.0", purl: "pkg:apk/alpine/curl@8.8.0", type: "library" },
    ];
    const filtered = filterComponents(components, "pkg:apk/alpine/open");
    expect(filtered).toHaveLength(1);
    expect(filtered[0].name).toBe("openssl");
  });

  it("Verification failure shows failure_reason", () => {
    const failure: SbomVerificationResponse = {
      ...runningVerification,
      status: "failed",
      failure_reason: "rekor entry missing",
    };
    const failedDetail = { ...detail, record: { ...detail.record, verification_status: "failed" as const } };
    const html = renderToStaticMarkup(<SBOMVerifyPanel client={client} detail={failedDetail} initialVerification={failure} />);
    expect(html).toContain("rekor entry missing");
  });
});
