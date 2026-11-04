import { Video } from "@remotion/media";
import {
  AbsoluteFill,
  Easing,
  Sequence,
  Track,
  interpolate,
  staticFile,
  useCurrentFrame,
} from "remotion";

const colors = {
  ink: "#0b1b1e",
  inkSoft: "#12292c",
  paper: "#f1f2e8",
  white: "#fbfcf5",
  muted: "#a9bbb1",
  green: "#b8e36b",
  teal: "#67d1bc",
  amber: "#f4c66a",
  line: "rgba(215, 236, 216, 0.17)",
};

const sceneFrames = {
  opening: 360,
  map: 300,
  footage: 3976,
  evidence: 390,
  boundary: 374,
};

const fade = (frame: number, duration = 24) =>
  interpolate(frame, [0, duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

const Brand = ({ light = false }: { readonly light?: boolean }) => (
  <div
    style={{
      color: light ? colors.ink : colors.paper,
      fontFamily: "Arial, Helvetica, sans-serif",
      fontSize: 24,
      fontWeight: 800,
      letterSpacing: "0.17em",
    }}
  >
    SOVRA
  </div>
);

const Eyebrow = ({ children }: { readonly children: string }) => (
  <div
    style={{
      color: colors.green,
      fontFamily: "Arial, Helvetica, sans-serif",
      fontSize: 22,
      fontWeight: 800,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
    }}
  >
    {children}
  </div>
);

const AccentPill = ({ children }: { readonly children: string }) => (
  <div
    style={{
      background: "rgba(184, 227, 107, 0.13)",
      border: "1px solid rgba(184, 227, 107, 0.44)",
      borderRadius: 999,
      color: colors.green,
      display: "inline-flex",
      fontFamily: "Arial, Helvetica, sans-serif",
      fontSize: 21,
      fontWeight: 700,
      letterSpacing: "0.08em",
      padding: "12px 20px",
    }}
  >
    {children}
  </div>
);

const Grid = () => (
  <AbsoluteFill
    style={{
      backgroundImage:
        "linear-gradient(rgba(215,236,216,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(215,236,216,0.035) 1px, transparent 1px)",
      backgroundSize: "80px 80px",
      opacity: 0.5,
    }}
  />
);

const OpeningScene = () => {
  const frame = useCurrentFrame();
  const opacity = fade(frame, 30);
  const rise = interpolate(frame, [0, 30], [36, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  const ring = interpolate(frame, [0, 48], [0.72, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <AbsoluteFill
      style={{
        background:
          "radial-gradient(circle at 78% 30%, rgba(103,209,188,0.13), transparent 34%), radial-gradient(circle at 18% 82%, rgba(184,227,107,0.10), transparent 36%), #0b1b1e",
        color: colors.paper,
        fontFamily: "Arial, Helvetica, sans-serif",
        padding: "82px 112px",
      }}
    >
      <Grid />
      <AbsoluteFill style={{ padding: "82px 112px" }}>
        <div style={{ alignItems: "center", display: "flex", justifyContent: "space-between" }}>
          <Brand />
          <AccentPill>FIXTURE · LIVE AI OFF</AccentPill>
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            marginTop: 80,
            opacity,
            translate: `0px ${rise}px`,
          }}
        >
          <Eyebrow>Synthetic product walkthrough</Eyebrow>
          <h1
            style={{
              color: colors.white,
              fontSize: 100,
              fontWeight: 750,
              letterSpacing: "-0.055em",
              lineHeight: 1.02,
              margin: "28px 0 0",
              maxWidth: 1360,
            }}
          >
            Ask one question.
            <br />
            <span style={{ color: colors.green }}>Prove only the answer.</span>
          </h1>
          <p
            style={{
              color: colors.muted,
              fontSize: 42,
              lineHeight: 1.35,
              margin: "38px 0 0",
              maxWidth: 1080,
            }}
          >
            One age check across four unfamiliar credential schemas.
          </p>
        </div>
        <div
          style={{
            alignItems: "center",
            bottom: 72,
            display: "flex",
            gap: 24,
            left: 112,
            position: "absolute",
          }}
        >
          <div
            style={{
              border: `1px solid ${colors.teal}`,
              borderRadius: "50%",
              height: 24,
              scale: ring,
              width: 24,
            }}
          />
          <span style={{ color: colors.muted, fontSize: 26 }}>Local synthetic flow · recorded from the running demo</span>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const SchemaCard = ({
  name,
  field,
  result,
  refused = false,
  delay,
}: {
  readonly name: string;
  readonly field: string;
  readonly result: string;
  readonly refused?: boolean;
  readonly delay: number;
}) => {
  const frame = useCurrentFrame();
  const opacity = fade(frame - delay, 24);
  const offset = interpolate(frame - delay, [0, 24], [30, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <div
      style={{
        background: "rgba(251,252,245,0.045)",
        border: `1px solid ${refused ? "rgba(244,198,106,0.5)" : colors.line}`,
        borderRadius: 20,
        minHeight: 170,
        opacity,
        padding: "25px 28px",
        translate: `0px ${offset}px`,
      }}
    >
      <div style={{ color: colors.muted, fontSize: 24, fontWeight: 700, letterSpacing: "0.06em" }}>{name}</div>
      <div style={{ color: colors.white, fontSize: 32, fontWeight: 700, marginTop: 18 }}>{field}</div>
      <div style={{ color: refused ? colors.amber : colors.green, fontSize: 25, fontWeight: 800, marginTop: 18 }}>
        {result}
      </div>
    </div>
  );
};

const FlowScene = () => {
  const frame = useCurrentFrame();
  const opacity = fade(frame, 24);
  const arrowWidth = interpolate(frame, [12, 70], [0, 100], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <AbsoluteFill
      style={{
        background:
          "radial-gradient(circle at 50% 115%, rgba(103,209,188,0.12), transparent 42%), #0b1b1e",
        color: colors.paper,
        fontFamily: "Arial, Helvetica, sans-serif",
        padding: "82px 112px",
      }}
    >
      <Grid />
      <AbsoluteFill style={{ padding: "82px 112px", opacity }}>
        <div style={{ alignItems: "center", display: "flex", justifyContent: "space-between" }}>
          <Brand />
          <Eyebrow>How the proof stays scoped</Eyebrow>
        </div>
        <h2
          style={{
            color: colors.white,
            fontSize: 86,
            letterSpacing: "-0.045em",
            lineHeight: 1.05,
            margin: "52px 0 18px",
          }}
        >
          Same intent. Different schemas.
        </h2>
        <p style={{ color: colors.muted, fontSize: 40, margin: 0 }}>
          The fixture planner proposes. A deterministic guard decides.
        </p>

        <div style={{ alignItems: "center", display: "flex", gap: 22, marginTop: 68 }}>
          <div
            style={{
              background: "rgba(103,209,188,0.10)",
              border: "1px solid rgba(103,209,188,0.5)",
              borderRadius: 18,
              minWidth: 320,
              padding: "24px 28px",
            }}
          >
            <div style={{ color: colors.teal, fontSize: 22, fontWeight: 800, letterSpacing: "0.12em" }}>REQUEST</div>
            <div style={{ color: colors.white, fontSize: 32, fontWeight: 700, marginTop: 14 }}>age_over_18</div>
            <div style={{ color: colors.muted, fontSize: 25, marginTop: 8 }}>one boolean result</div>
          </div>
          <div style={{ background: colors.teal, height: 2, opacity: arrowWidth / 100, width: 110 }} />
          <div
            style={{
              background: "rgba(184,227,107,0.09)",
              border: "1px solid rgba(184,227,107,0.48)",
              borderRadius: 18,
              minWidth: 330,
              padding: "24px 28px",
            }}
          >
            <div style={{ color: colors.green, fontSize: 22, fontWeight: 800, letterSpacing: "0.12em" }}>PLANNER · FIXTURE</div>
            <div style={{ color: colors.white, fontSize: 31, fontWeight: 700, marginTop: 14 }}>candidate map</div>
            <div style={{ color: colors.muted, fontSize: 25, marginTop: 8 }}>not a live model call</div>
          </div>
          <div style={{ background: colors.teal, height: 2, opacity: arrowWidth / 100, width: 110 }} />
          <div
            style={{
              background: "rgba(244,198,106,0.08)",
              border: "1px solid rgba(244,198,106,0.48)",
              borderRadius: 18,
              minWidth: 330,
              padding: "24px 28px",
            }}
          >
            <div style={{ color: colors.amber, fontSize: 22, fontWeight: 800, letterSpacing: "0.12em" }}>GUARD</div>
            <div style={{ color: colors.white, fontSize: 31, fontWeight: 700, marginTop: 14 }}>accept or NO_PATH</div>
            <div style={{ color: colors.muted, fontSize: 25, marginTop: 8 }}>independent policy check</div>
          </div>
        </div>

        <div style={{ display: "grid", gap: 18, gridTemplateColumns: "repeat(4, 1fr)", marginTop: 44 }}>
          <SchemaCard name="KNOWN" field="adultOver18" result="accepted" delay={6} />
          <SchemaCard name="FJORD" field="isAdult" result="accepted" delay={12} />
          <SchemaCard name="HARBOR" field="qualifiesAsAdult" result="accepted" delay={18} />
          <SchemaCard name="EMPLOYMENT" field="tenure" result="NO_PATH · no artifact" refused delay={24} />
        </div>
        <div style={{ bottom: 62, color: colors.muted, fontSize: 25, left: 112, position: "absolute" }}>
          These cases are shown in the recorded synthetic browser journey.
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const RecordedJourney = () => {
  return (
    <AbsoluteFill
      style={{
        alignItems: "center",
        background:
          "radial-gradient(circle at 50% 50%, #1b3536 0%, #0b1b1e 66%, #071315 100%)",
        display: "flex",
        justifyContent: "center",
        padding: 90,
      }}
    >
      <div
        style={{
          border: "1px solid rgba(224,244,224,0.27)",
          borderRadius: 14,
          boxShadow: "0 34px 120px rgba(0,0,0,0.38)",
          height: 900,
          overflow: "hidden",
          width: 1440,
        }}
      >
        <Video
          name="Real synthetic browser journey"
          src={staticFile("sovra-synthetic-demo.mp4")}
          muted
          objectFit="contain"
          style={{ height: "100%", width: "100%" }}
        />
      </div>
    </AbsoluteFill>
  );
};

const EvidenceScene = () => {
  const frame = useCurrentFrame();
  const opacity = fade(frame, 22);

  return (
    <AbsoluteFill
      style={{
        background:
          "radial-gradient(circle at 100% 0%, rgba(184,227,107,0.11), transparent 30%), #f1f2e8",
        color: colors.ink,
        fontFamily: "Arial, Helvetica, sans-serif",
        opacity,
        padding: "76px 112px",
      }}
    >
      <div style={{ alignItems: "center", display: "flex", justifyContent: "space-between" }}>
        <Brand light />
        <div style={{ color: "#3c5f56", fontSize: 22, fontWeight: 800, letterSpacing: "0.13em" }}>WHAT THE RUN SHOWS</div>
      </div>
      <h2
        style={{
          color: colors.ink,
          fontSize: 72,
          letterSpacing: "-0.05em",
          lineHeight: 1.06,
          margin: "56px 0 44px",
          maxWidth: 1450,
        }}
      >
        Different claim names. The same minimal answer.
      </h2>
      <div style={{ display: "grid", gap: 22, gridTemplateColumns: "1fr 1fr" }}>
        <div
          style={{
            background: colors.white,
            border: "1px solid rgba(11,27,30,0.12)",
            borderRadius: 24,
            minHeight: 318,
            padding: 34,
          }}
        >
          <div style={{ color: "#527168", fontSize: 23, fontWeight: 800, letterSpacing: "0.12em" }}>ACCEPTED</div>
          <div style={{ color: colors.ink, fontSize: 39, fontWeight: 750, lineHeight: 1.2, marginTop: 24 }}>
            Fjord · Harbor
          </div>
          <div style={{ color: "#405650", fontSize: 30, lineHeight: 1.45, marginTop: 22 }}>
            `isAdult` and `qualifiesAsAdult` both map to one age-over-18 result.
          </div>
          <div style={{ color: "#527168", fontSize: 25, fontWeight: 700, marginTop: 24 }}>
            Holder reviews the exact claim before consent.
          </div>
        </div>
        <div
          style={{
            background: colors.white,
            border: "1px solid rgba(11,27,30,0.12)",
            borderRadius: 24,
            minHeight: 318,
            padding: 34,
          }}
        >
          <div style={{ color: "#9b671d", fontSize: 23, fontWeight: 800, letterSpacing: "0.12em" }}>REFUSED</div>
          <div style={{ color: colors.ink, fontSize: 39, fontWeight: 750, lineHeight: 1.2, marginTop: 24 }}>
            Employment tenure
          </div>
          <div style={{ color: "#405650", fontSize: 30, lineHeight: 1.45, marginTop: 22 }}>
            Incompatible evidence returns `NO_PATH`: no plan, credential, or consent request.
          </div>
          <div style={{ color: "#9b671d", fontSize: 25, fontWeight: 700, marginTop: 24 }}>
            A refusal is a valid result.
          </div>
        </div>
      </div>
      <div style={{ bottom: 72, color: "#527168", fontSize: 25, left: 112, position: "absolute" }}>
        Captured from real browser requests to the local synthetic backends.
      </div>
    </AbsoluteFill>
  );
};

const BoundaryScene = () => {
  const frame = useCurrentFrame();
  const opacity = fade(frame, 20);
  const slide = interpolate(frame, [0, 20], [26, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <AbsoluteFill
      style={{
        background:
          "radial-gradient(circle at 15% 110%, rgba(103,209,188,0.10), transparent 37%), #0b1b1e",
        color: colors.paper,
        fontFamily: "Arial, Helvetica, sans-serif",
        padding: "70px 112px",
      }}
    >
      <Grid />
      <AbsoluteFill style={{ padding: "70px 112px", opacity, translate: `0px ${slide}px` }}>
        <div style={{ alignItems: "center", display: "flex", justifyContent: "space-between" }}>
          <Brand />
          <AccentPill>SYNTHETIC · FIXTURE · LIVE AI OFF</AccentPill>
        </div>
        <h2
          style={{
            color: colors.white,
            fontSize: 74,
            letterSpacing: "-0.045em",
            lineHeight: 1.08,
            margin: "42px 0 36px",
          }}
        >
          What this video does not claim.
        </h2>
        <div style={{ display: "grid", gap: 24, gridTemplateColumns: "1fr 1fr" }}>
          <div style={{ borderTop: `2px solid ${colors.green}`, paddingTop: 22 }}>
            <div style={{ color: colors.green, fontSize: 25, fontWeight: 800, letterSpacing: "0.11em" }}>DEMONSTRATED</div>
            <ul style={{ color: colors.white, fontSize: 31, lineHeight: 1.55, margin: "18px 0 0", paddingLeft: 34 }}>
              <li>Fictional issuers and synthetic credentials</li>
              <li>Fixture planning and deterministic guard</li>
              <li>Explicit consent and a scoped result</li>
            </ul>
          </div>
          <div style={{ borderTop: `2px solid ${colors.amber}`, paddingTop: 22 }}>
            <div style={{ color: colors.amber, fontSize: 25, fontWeight: 800, letterSpacing: "0.11em" }}>NOT DEMONSTRATED</div>
            <ul style={{ color: colors.white, fontSize: 31, lineHeight: 1.55, margin: "18px 0 0", paddingLeft: 34 }}>
              <li>A live model call or legal KYC decision</li>
              <li>Production keys, data, or hosting</li>
              <li>External wallet or protocol conformance</li>
            </ul>
          </div>
        </div>
        <div
          style={{
            borderTop: `1px solid ${colors.line}`,
            bottom: 62,
            color: colors.muted,
            fontSize: 24,
            left: 112,
            paddingTop: 18,
            position: "absolute",
            right: 112,
          }}
        >
          Local synthetic evidence only · verify current release and deployment status separately
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

export const SovraThreeMinute = () => {
  return (
    <Track name="Sovra three-minute walkthrough">
      <Sequence name="Opening" durationInFrames={sceneFrames.opening}>
        <OpeningScene />
      </Sequence>
      <Sequence name="Intent and guard" from={sceneFrames.opening} durationInFrames={sceneFrames.map}>
        <FlowScene />
      </Sequence>
      <Sequence
        name="Recorded browser journey"
        from={sceneFrames.opening + sceneFrames.map}
        durationInFrames={sceneFrames.footage}
      >
        <RecordedJourney />
      </Sequence>
      <Sequence
        name="Evidence summary"
        from={sceneFrames.opening + sceneFrames.map + sceneFrames.footage}
        durationInFrames={sceneFrames.evidence}
      >
        <EvidenceScene />
      </Sequence>
      <Sequence
        name="Limits and close"
        from={sceneFrames.opening + sceneFrames.map + sceneFrames.footage + sceneFrames.evidence}
        durationInFrames={sceneFrames.boundary}
      >
        <BoundaryScene />
      </Sequence>
    </Track>
  );
};

export const TOTAL_FRAMES =
  sceneFrames.opening +
  sceneFrames.map +
  sceneFrames.footage +
  sceneFrames.evidence +
  sceneFrames.boundary;
