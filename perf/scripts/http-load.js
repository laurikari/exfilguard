import http from "k6/http";
import { check } from "k6";
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

const target = __ENV.TARGET || "http://upstream/";
const steadyRate = Number(__ENV.RATE || 500);
const steadyDuration = __ENV.DURATION || "15s";
const preAllocatedVUs = Number(__ENV.VUS || 100);
const maxVUs = Number(__ENV.MAX_VUS || preAllocatedVUs * 2);

const rampEnabled = (__ENV.RAMP || "0").toLowerCase() === "1" || (__ENV.RAMP || "").toLowerCase() === "true";
const rampStart = Number(__ENV.RAMP_START_RATE || steadyRate);
const rampStep = Number(__ENV.RAMP_STEP || 250);
const rampStages = Number(__ENV.RAMP_STAGES || 4);
const rampStageDuration = __ENV.RAMP_STAGE_DURATION || "30s";

const rampStagesConfig = Array.from({ length: rampStages }, (_, idx) => ({
  target: rampStart + rampStep * idx,
  duration: rampStageDuration,
}));

const scenarios = rampEnabled
  ? {
      ramp_load: {
        executor: "ramping-arrival-rate",
        timeUnit: "1s",
        startRate: rampStart,
        preAllocatedVUs,
        maxVUs,
        stages: rampStagesConfig,
      },
    }
  : {
      steady_rate: {
        executor: "constant-arrival-rate",
        rate: steadyRate,
        timeUnit: "1s",
        duration: steadyDuration,
        preAllocatedVUs,
        maxVUs,
      },
    };

export const options = {
  scenarios,
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<200"],
  },
};

export default function () {
  const res = http.get(target);
  check(res, {
    "status is 200": (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  return {
    "/results/summary.html": htmlReport(data),
  };
}
