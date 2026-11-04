import { Video } from "@remotion/media";
import type { CSSProperties } from "react";
import {
  AbsoluteFill,
  Easing,
  Img,
  Sequence,
  Track,
  interpolate,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

const ink = "#12243a";
const paper = "#f8f9f4";
const cobalt = "#2855e8";
const lemon = "#e8ff57";
const coral = "#ff7054";
const mint = "#77e2c6";
const lilac = "#c9bbff";
const muted = "#4b5e72";
const display = "Georgia, 'Times New Roman', serif";
const sans = "Arial, Helvetica, sans-serif";
const mono = "'SFMono-Regular', Consolas, 'Liberation Mono', monospace";

const sceneFrames = {
  problem: 360,
  apps: 420,
  coreCompose: 540,
  issuerCompose: 540,
  json: 660,
  holder: 600,
  recordedRun: 420,
  appOutcome: 420,
  encryption: 720,
  refusal: 360,
  close: 360,
};

const easeIn = (frame: number, delay = 0, duration = 22) =>
  interpolate(frame - delay, [0, duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

const SceneCopy = ({
  frame,
  title,
  body,
  top = 185,
  width = 650,
  dark = false,
  titleSize = 76,
}: {
  readonly frame: number;
  readonly title: string;
  readonly body: string;
  readonly top?: number;
  readonly width?: number;
  readonly dark?: boolean;
  readonly titleSize?: number;
}) => {
  const opacity = easeIn(frame, 5, 25);
  const rise = interpolate(frame, [0, 30], [24, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <div
      style={{
        color: dark ? paper : ink,
        opacity,
        position: "absolute",
        right: 92,
        top,
        translate: `0px ${rise}px`,
        width,
      }}
    >
      <h1
        style={{
          fontFamily: display,
          fontSize: titleSize,
          fontWeight: 700,
          letterSpacing: "-0.028em",
          lineHeight: 1.03,
          margin: 0,
          maxWidth: "10ch",
        }}
      >
        {title}
      </h1>
      <p
        style={{
          color: dark ? "#d6e3f0" : muted,
          fontFamily: sans,
          fontSize: 29,
          lineHeight: 1.43,
          margin: "28px 0 0",
          maxWidth: "24ch",
        }}
      >
        {body}
      </p>
    </div>
  );
};

const Label = ({
  children,
  style,
}: {
  readonly children: string;
  readonly style?: CSSProperties;
}) => (
  <span
    style={{
      color: ink,
      display: "inline-flex",
      fontFamily: sans,
      fontSize: 19,
      fontWeight: 800,
      letterSpacing: "0.04em",
      ...style,
    }}
  >
    {children}
  </span>
);

const DiagramBlock = ({
  title,
  detail,
  x,
  y,
  width,
  height = 96,
  fill = "#ffffff",
  color = ink,
  border = "rgba(18,36,58,0.14)",
  delay = 0,
  frame,
  small = false,
}: {
  readonly title: string;
  readonly detail?: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height?: number;
  readonly fill?: string;
  readonly color?: string;
  readonly border?: string;
  readonly delay?: number;
  readonly frame: number;
  readonly small?: boolean;
}) => {
  const opacity = easeIn(frame, delay, 16);
  const move = interpolate(frame - delay, [0, 18], [16, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  return (
    <div
      style={{
        background: fill,
        border: `2px solid ${border}`,
        borderRadius: 16,
        boxSizing: "border-box",
        color,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        left: x,
        minWidth: 0,
        opacity,
        padding: small ? "14px 18px" : "18px 22px",
        position: "absolute",
        top: y + move,
        width,
        height,
      }}
    >
      <strong style={{ fontFamily: sans, fontSize: small ? 21 : 26, lineHeight: 1.1 }}>{title}</strong>
      {detail && (
        <span style={{ color: color === paper ? "#d4e1ec" : muted, fontFamily: sans, fontSize: small ? 16 : 18, marginTop: 9 }}>
          {detail}
        </span>
      )}
    </div>
  );
};

const AppWindow = ({
  src,
  name,
  x,
  y,
  width,
  frame,
  delay = 0,
  rotate = "0deg",
}: {
  readonly src: string;
  readonly name: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly frame: number;
  readonly delay?: number;
  readonly rotate?: string;
}) => {
  const opacity = easeIn(frame, delay, 26);
  const rise = interpolate(frame - delay, [0, 26], [34, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  return (
    <div
      style={{
        background: paper,
        border: "2px solid rgba(18,36,58,0.18)",
        borderRadius: 18,
        boxShadow: "0 24px 70px rgba(18,36,58,0.17)",
        left: x,
        opacity,
        overflow: "hidden",
        position: "absolute",
        top: y + rise,
        transform: `rotate(${rotate})`,
        width,
      }}
    >
      <div style={{ alignItems: "center", background: "#ffffff", display: "flex", height: 37, padding: "0 14px" }}>
        <div style={{ display: "flex", gap: 5 }}>
          {[coral, lemon, mint].map((color) => (
            <span key={color} style={{ background: color, borderRadius: "50%", height: 8, width: 8 }} />
          ))}
        </div>
        <span style={{ color: muted, fontFamily: sans, fontSize: 13, fontWeight: 700, marginLeft: 14 }}>{name}</span>
      </div>
      <Img src={staticFile(src)} style={{ display: "block", height: "auto", width: "100%" }} />
    </div>
  );
};

const ProblemScene = () => {
  const frame = useCurrentFrame();
  const excess = interpolate(frame, [150, 230], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const answer = easeIn(frame, 190, 38);
  const fieldRows = [
    { label: "date of birth", value: "•• / •• / ••••" },
    { label: "document number", value: "•••• •••• ••••" },
    { label: "home address", value: "street · city · postcode" },
  ];

  return (
    <AbsoluteFill style={{ background: "#f3f4ed", color: ink, fontFamily: sans }}>
      <div style={{ background: mint, borderRadius: 32, height: 690, left: 80, position: "absolute", top: 170, width: 1000 }} />
      <div style={{ background: paper, border: "2px solid rgba(18,36,58,0.16)", borderRadius: 22, left: 140, padding: 32, position: "absolute", top: 226, width: 670 }}>
        <div style={{ color: muted, fontSize: 20, fontWeight: 800, letterSpacing: "0.05em" }}>THE QUESTION</div>
        <div style={{ fontFamily: display, fontSize: 55, fontWeight: 700, marginTop: 14 }}>Are you over 18?</div>
        <div style={{ background: ink, borderRadius: 12, color: lemon, display: "inline-flex", fontFamily: mono, fontSize: 24, marginTop: 20, padding: "12px 18px" }}>
          age_over_18
        </div>
      </div>
      {fieldRows.map((row, index) => {
        const rowOpacity = excess * easeIn(frame, 30 + index * 14, 18);
        const offset = interpolate(frame - (30 + index * 14), [0, 18], [18, 0], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
          easing: Easing.bezier(0.16, 1, 0.3, 1),
        });
        return (
          <div
            key={row.label}
            style={{
              alignItems: "center",
              background: "#ffffff",
              border: `2px solid ${coral}`,
              borderRadius: 14,
              display: "flex",
              justifyContent: "space-between",
              left: 190,
              opacity: rowOpacity,
              padding: "15px 20px",
              position: "absolute",
              top: 475 + index * 86 + offset,
              width: 570,
            }}
          >
            <span style={{ color: muted, fontSize: 20, fontWeight: 700 }}>{row.label}</span>
            <span style={{ color: ink, fontFamily: mono, fontSize: 19 }}>{row.value}</span>
          </div>
        );
      })}
      <div
        style={{
          background: lemon,
          border: `2px solid ${ink}`,
          borderRadius: 18,
          boxShadow: "0 18px 48px rgba(18,36,58,0.14)",
          color: ink,
          fontFamily: mono,
          fontSize: 31,
          fontWeight: 800,
          left: 250,
          opacity: answer,
          padding: "24px 32px",
          position: "absolute",
          top: 682,
          translate: `0px ${interpolate(frame, [190, 228], [26, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })}px`,
        }}
      >
        one fact · yes
      </div>
      <SceneCopy frame={frame} title="One quick check can ask for too much." body="Imagine an age gate that asks for a full identity record just to answer one question." top={215} width={680} />
      <div style={{ bottom: 74, color: muted, fontFamily: sans, fontSize: 20, left: 108, position: "absolute" }}>
        The problem: schemas differ, so relying parties often over-ask.
      </div>
    </AbsoluteFill>
  );
};

const AppsScene = () => {
  const frame = useCurrentFrame();
  const cardLabel = easeIn(frame, 28, 22);
  return (
    <AbsoluteFill style={{ background: lemon, color: ink, fontFamily: sans }}>
      <div style={{ background: coral, borderRadius: 38, height: 760, left: 72, position: "absolute", top: 142, width: 1090 }} />
      <AppWindow src="product-scenes/novabank-request.png" name="NovaBank · demo onboarding" x={115} y={194} width={770} frame={frame} delay={8} rotate="-1.2deg" />
      <AppWindow src="product-scenes/cornercellar-request.png" name="CornerCellar · demo age gate" x={430} y={485} width={580} frame={frame} delay={32} rotate="1.3deg" />
      <div style={{ background: paper, borderRadius: 14, bottom: 119, left: 133, opacity: cardLabel, padding: "17px 23px", position: "absolute" }}>
        <Label>One purpose-bound request</Label>
      </div>
      <SceneCopy frame={frame} title="Two apps ask for the same answer." body="NovaBank onboarding and CornerCellar checkout need one fact: age eligibility. Both are fictional browser demos." top={218} width={615} />
    </AbsoluteFill>
  );
};

const Connector = ({
  d,
  frame,
  delay = 0,
  color = cobalt,
  dash = false,
}: {
  readonly d: string;
  readonly frame: number;
  readonly delay?: number;
  readonly color?: string;
  readonly dash?: boolean;
}) => {
  const progress = easeIn(frame, delay, 32);
  return (
    <svg height="700" style={{ height: 700, left: 0, overflow: "visible", pointerEvents: "none", position: "absolute", top: 0, width: 1050 }} viewBox="0 0 1050 700">
      <defs>
        <marker id={`arrow-${color.replace("#", "")}-${delay}`} markerHeight="9" markerWidth="9" orient="auto" refX="8" refY="4.5">
          <path d="M0,0 L9,4.5 L0,9 z" fill={color} />
        </marker>
      </defs>
      <path
        d={d}
        fill="none"
        markerEnd={`url(#arrow-${color.replace("#", "")}-${delay})`}
        pathLength={1}
        stroke={color}
        strokeDasharray={dash ? "8 12" : `${progress} 1`}
        strokeDashoffset={dash ? 0 : 0}
        strokeLinecap="round"
        strokeWidth={4}
        style={{ opacity: dash ? progress : 0.94 }}
      />
    </svg>
  );
};

const CoreComposeScene = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ background: paper, color: ink, fontFamily: sans }}>
      <div style={{ background: "#eef1ff", border: `3px solid ${cobalt}`, borderRadius: 26, height: 730, left: 70, position: "absolute", top: 150, width: 1000 }} />
      <div style={{ background: cobalt, borderRadius: "0 0 15px 15px", color: "#ffffff", fontSize: 20, fontWeight: 800, left: 104, padding: "11px 20px", position: "absolute", top: 150 }}>
        compose.yaml · core app stack
      </div>
      <div style={{ height: 730, left: 70, position: "absolute", top: 150, width: 1000 }}>
        <Connector d="M225 185 V238 H215 V293" frame={frame} delay={25} color={cobalt} />
        <Connector d="M225 238 H550 V293" frame={frame} delay={45} color={cobalt} />
        <Connector d="M350 392 V472 H665 V528" frame={frame} delay={70} color={coral} />
        <Connector d="M680 392 V528" frame={frame} delay={92} color={coral} />
        <Connector d="M350 600 H640" frame={frame} delay={115} color={coral} />
      </div>
      <DiagramBlock frame={frame} title="Keycloak" detail="operator identity" x={116} y={233} width={250} fill={lilac} border={lilac} delay={12} />
      <DiagramBlock frame={frame} title="db-seed" detail="one-shot setup" x={705} y={233} width={230} fill={lemon} border={lemon} delay={24} />
      <DiagramBlock frame={frame} title="app-a" detail="backend instance" x={116} y={382} width={300} delay={34} />
      <DiagramBlock frame={frame} title="app-b" detail="backend instance" x={470} y={382} width={300} delay={48} />
      <DiagramBlock frame={frame} title="quarantine-worker" detail="isolated file work" x={116} y={540} width={360} height={110} fill="#ffe2d9" border="#ffc4b3" delay={65} />
      <DiagramBlock frame={frame} title="PostgreSQL" detail="one shared database" x={612} y={540} width={340} height={110} fill={ink} color={paper} border={ink} delay={78} />
      <SceneCopy frame={frame} title="The core stack runs two app instances." body="PostgreSQL, Keycloak, a seed job and a quarantine worker support app-a and app-b. Both app instances use the same database." top={245} width={650} />
      <div style={{ bottom: 62, color: muted, fontFamily: sans, fontSize: 18, left: 112, position: "absolute" }}>
        One Compose topology · shared data plane · no claim of issuer-level separation here
      </div>
    </AbsoluteFill>
  );
};

const IssuerComposeScene = () => {
  const frame = useCurrentFrame();
  const boundary = easeIn(frame, 5, 24);
  return (
    <AbsoluteFill style={{ background: "#eaf8f3", color: ink, fontFamily: sans }}>
      <div style={{ border: "2px dashed rgba(18,36,58,0.4)", borderRadius: 30, height: 700, left: 56, opacity: boundary, position: "absolute", top: 172, width: 1260 }} />
      <div style={{ background: ink, borderRadius: "0 0 14px 14px", color: paper, fontSize: 18, fontWeight: 800, left: 88, padding: "10px 16px", position: "absolute", top: 172 }}>
        compose.demo-issuers.yaml · separate local demo stack
      </div>
      <div style={{ background: lemon, border: `2px solid ${ink}`, borderRadius: 18, display: "grid", height: 100, left: 86, padding: 16, placeContent: "center", position: "absolute", textAlign: "center", top: 470, width: 240 }}>
        <strong style={{ fontSize: 23 }}>Demo router</strong>
        <span style={{ color: muted, fontSize: 17, marginTop: 8 }}>central plan → issuer route</span>
      </div>
      <Connector d="M326 520 H405" frame={frame} delay={30} color={cobalt} />
      <Connector d="M785 520 H863" frame={frame} delay={92} color={coral} />
      <div style={{ background: "#e0e9ff", border: `2px solid ${cobalt}`, borderRadius: 24, height: 540, left: 405, position: "absolute", top: 260, width: 360 }} />
      <div style={{ background: "#ffe2d9", border: `2px solid ${coral}`, borderRadius: 24, height: 540, left: 865, position: "absolute", top: 260, width: 360 }} />
      <DiagramBlock frame={frame} title="Node A" detail="planner + guard + synth-1" x={432} y={320} width={305} fill={cobalt} color="#ffffff" border={cobalt} delay={24} />
      <DiagramBlock frame={frame} title="db-a" detail="own credential store" x={432} y={540} width={305} fill="#ffffff" border="#b9c9ff" delay={48} />
      <DiagramBlock frame={frame} title="key A" detail="signs synth-1 only" x={432} y={665} width={305} height={78} fill={lemon} border={lemon} delay={62} small />
      <DiagramBlock frame={frame} title="Node B" detail="issuer synth-2" x={892} y={320} width={305} fill={coral} color={ink} border={coral} delay={80} />
      <DiagramBlock frame={frame} title="db-b" detail="own credential store" x={892} y={540} width={305} fill="#ffffff" border="#ffb7a7" delay={98} />
      <DiagramBlock frame={frame} title="key B" detail="signs synth-2 only" x={892} y={665} width={305} height={78} fill={lemon} border={lemon} delay={112} small />
      <div style={{ background: "#ffffff", border: "1px solid rgba(18,36,58,0.14)", borderRadius: 11, color: muted, fontSize: 16, left: 680, padding: "8px 12px", position: "absolute", top: 218 }}>
        public trust metadata copied to both nodes
      </div>
      <SceneCopy frame={frame} title="Issuer nodes keep stores and keys apart." body="The plan selects the issuer. Its node owns the signing key and credential rows; public trust metadata is shared. Both stacks still run on one developer host." top={222} width={520} titleSize={69} />
      <div style={{ background: lemon, borderRadius: 12, bottom: 63, color: ink, fontSize: 19, fontWeight: 800, left: 92, padding: "12px 18px", position: "absolute" }}>
        Local logical separation · not sovereign-host isolation
      </div>
    </AbsoluteFill>
  );
};

const JsonPanel = ({
  heading,
  content,
  x,
  y,
  width,
  height,
  fill,
  frame,
  delay,
  textSize = 22,
}: {
  readonly heading: string;
  readonly content: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly fill: string;
  readonly frame: number;
  readonly delay: number;
  readonly textSize?: number;
}) => {
  const opacity = easeIn(frame, delay, 20);
  return (
    <div
      style={{
        background: fill,
        border: `2px solid ${ink}`,
        borderRadius: 18,
        boxShadow: "0 16px 0 rgba(18,36,58,0.10)",
        boxSizing: "border-box",
        color: ink,
        left: x,
        opacity,
        padding: "19px 20px",
        position: "absolute",
        top: y,
        width,
        height,
      }}
    >
      <div style={{ fontFamily: sans, fontSize: 18, fontWeight: 800, marginBottom: 15 }}>{heading}</div>
      <pre style={{ fontFamily: mono, fontSize: textSize, lineHeight: 1.56, margin: 0, whiteSpace: "pre-wrap" }}>{content}</pre>
    </div>
  );
};

const JsonScene = () => {
  const frame = useCurrentFrame();
  const packet = interpolate(frame, [70, 170], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ background: lemon, color: ink, fontFamily: sans }}>
      <JsonPanel frame={frame} delay={8} heading="BROWSER REQUEST" content={'{\n  "case": "fjord"\n}'} x={70} y={280} width={290} height={190} fill="#ffffff" textSize={24} />
      <JsonPanel
        frame={frame}
        delay={28}
        heading="RETURNED PLAN · KEY FIELDS"
        content={'{\n  "recommendation":\n    "CANDIDATE_ONLY",\n  "candidate_issuer_id":\n    "https://sovra.example/issuers/synth-2",\n  "claim_paths": ["isAdult"],\n  "requested_outcome":\n    "age_over_18"\n}'}
        x={418}
        y={220}
        width={440}
        height={410}
        fill="#dce5ff"
        textSize={19}
      />
      <JsonPanel
        frame={frame}
        delay={60}
        heading="DETERMINISTIC GUARD"
        content={'{\n  "accepted": true,\n  "code":\n    "GUARD_ACCEPTED",\n  "rulesVersion":\n    "sovra-guard/2",\n  "snapshotVersion": 3\n}'}
        x={894}
        y={302}
        width={350}
        height={380}
        fill="#c9f4e7"
        textSize={20}
      />
      <div style={{ background: cobalt, borderRadius: 4, height: 5, left: 350, opacity: packet, position: "absolute", top: 371, width: 93 }} />
      <div style={{ background: coral, borderRadius: 4, height: 5, left: 850, opacity: packet, position: "absolute", top: 460, width: 60 }} />
      <SceneCopy frame={frame} title="The browser asks for a case. The backend finds the field." body="For Fjord, the fixture planner returns isAdult on synth-2. The guard checks the returned plan; the browser never supplies that unfamiliar claim name." top={174} width={550} titleSize={68} />
      <div style={{ bottom: 70, color: muted, fontFamily: sans, fontSize: 18, left: 82, position: "absolute" }}>
        Selected fields from the actual local synthetic response; other fields are omitted.
      </div>
    </AbsoluteFill>
  );
};

const HolderScene = () => {
  const frame = useCurrentFrame();
  const glow = interpolate(frame, [0, 35, 90], [0.4, 1, 0.65], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ background: "#f2f0ff", color: ink, fontFamily: sans }}>
      <div style={{ background: lilac, borderRadius: 36, height: 728, left: 67, position: "absolute", top: 161, width: 1074 }} />
      <AppWindow src="product-scenes/fjord-consent.png" name="Fjord · holder consent" x={112} y={203} width={850} frame={frame} delay={10} />
      <div style={{ background: lemon, border: `2px solid ${ink}`, borderRadius: 17, boxShadow: "0 20px 48px rgba(18,36,58,0.18)", left: 522, opacity: glow, padding: "22px 26px", position: "absolute", top: 674 }}>
        <div style={{ color: muted, fontSize: 17, fontWeight: 800 }}>THE HOLDER REVIEWS</div>
        <div style={{ color: ink, fontFamily: mono, fontSize: 24, fontWeight: 800, marginTop: 10 }}>isAdult: true</div>
        <div style={{ color: muted, fontSize: 17, marginTop: 6 }}>issuer · purpose · expiry · plan hash</div>
      </div>
      <SceneCopy frame={frame} title="The holder sees the exact claim." body="Before anything is shared, the person can inspect who asks, what they learn, which issuer supplies it, and when it expires." top={232} width={600} />
    </AbsoluteFill>
  );
};

const RecordedRunScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  // The source recording reaches Fjord consent at 62.5 seconds, then ACCEPTED at 67.3.
  // trimBefore is measured in composition frames, so convert that source time using the composition fps.
  const sourceStart = 62.5 * fps;
  const clipOpacity = easeIn(frame, 6, 24);
  return (
    <AbsoluteFill style={{ background: "#182c4c", color: paper, fontFamily: sans }}>
      <div style={{ background: "#273f67", border: "2px solid rgba(255,255,255,0.28)", borderRadius: 22, boxShadow: "0 28px 80px rgba(0,0,0,0.28)", height: 592, left: 75, opacity: clipOpacity, overflow: "hidden", position: "absolute", top: 190, width: 970 }}>
        <Video
          name="Recorded Fjord consent and verification"
          src={staticFile("sovra-synthetic-demo.mp4")}
          trimBefore={sourceStart}
          muted
          objectFit="cover"
          style={{ height: "100%", width: "100%" }}
        />
      </div>
      <SceneCopy frame={frame} title="One consent. One issuer. One recorded result." body="The browser approves the synthetic Fjord request, the plan routes to synth-2, and verification returns ACCEPTED." top={230} width={670} dark titleSize={71} />
      <div style={{ bottom: 69, color: "#d6e3f0", fontFamily: sans, fontSize: 18, left: 92, position: "absolute" }}>
        Recorded from the running local browser · synthetic profile · live AI off
      </div>
    </AbsoluteFill>
  );
};

const EncryptionLane = ({
  frame,
  top,
  label,
  items,
  palette,
  delay,
}: {
  readonly frame: number;
  readonly top: number;
  readonly label: string;
  readonly items: Array<{ title: string; detail: string }>;
  readonly palette: string[];
  readonly delay: number;
}) => (
  <div style={{ background: "rgba(255,255,255,0.75)", border: "1px solid rgba(18,36,58,0.18)", borderRadius: 20, height: 296, left: 60, position: "absolute", top, width: 1170 }}>
    <div style={{ color: muted, fontFamily: sans, fontSize: 17, fontWeight: 800, left: 26, position: "absolute", top: 22 }}>{label}</div>
    {items.map((item, index) => (
      <DiagramBlock
        key={item.title}
        frame={frame}
        delay={delay + index * 15}
        title={item.title}
        detail={item.detail}
        x={27 + index * 222}
        y={92}
        width={195}
        height={132}
        fill={palette[index]}
        border={palette[index]}
        small
      />
    ))}
    {items.slice(0, -1).map((item, index) => (
      <div key={`${item.title}-arrow`} style={{ background: ink, height: 3, left: 224 + index * 222, opacity: easeIn(frame, delay + 30, 14), position: "absolute", top: 157, width: 26 }} />
    ))}
  </div>
);

const EncryptionScene = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ background: "#e2e8ff", color: ink, fontFamily: sans }}>
      <EncryptionLane
        frame={frame}
        top={101}
        label="CREDENTIAL SIGNING · issuer key path"
        delay={8}
        palette={["#ffd9cd", "#ffffff", "#fff2a5", "#c9f4e7"]}
        items={[
          { title: "issuer claim", detail: "synthetic · scoped" },
          { title: "P-256 / ES256", detail: "issuer signs" },
          { title: "holder consent", detail: "one exact claim" },
          { title: "verifier", detail: "trust + signature" },
        ]}
      />
      <EncryptionLane
        frame={frame}
        top={451}
        label="VAULT ENCRYPTION · separate backend code path"
        delay={74}
        palette={["#ffffff", "#fff2a5", "#c9f4e7", "#ffd9cd"]}
        items={[
          { title: "object version", detail: "fresh 256-bit DEK" },
          { title: "AES-256-GCM", detail: "12-byte nonce · identity-bound AAD" },
          { title: "ciphertext", detail: "tag checked on read" },
          { title: "wrapped DEK", detail: "versioned KEK · HKDF-SHA256" },
        ]}
      />
      <SceneCopy frame={frame} title="Signing and encryption solve different jobs." body="Credentials use an issuer signature. Vault objects use fresh per-version keys and AES-GCM. The local synthetic vault wraps keys in software; production KMS/HSM is still a gate." top={226} width={570} titleSize={66} />
      <div style={{ bottom: 39, color: muted, fontFamily: sans, fontSize: 16, left: 86, position: "absolute" }}>
        Vault cryptography is implemented in backend code; this age-check journey does not read vault documents.
      </div>
    </AbsoluteFill>
  );
};

const AppOutcomeScene = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ background: "#ffede7", color: ink, fontFamily: sans }}>
      <AppWindow src="product-scenes/novabank-accepted.png" name="NovaBank · recorded result" x={64} y={194} width={690} frame={frame} delay={6} rotate="-0.8deg" />
      <AppWindow src="product-scenes/cornercellar-accepted.png" name="CornerCellar · recorded result" x={510} y={416} width={690} frame={frame} delay={28} rotate="0.8deg" />
      <SceneCopy frame={frame} title="Same answer. Two different journeys." body="NovaBank records eligibility evidence. CornerCellar places a fictional demo order after the synthetic age check." top={187} width={580} titleSize={68} />
    </AbsoluteFill>
  );
};

const RefusalScene = () => {
  const frame = useCurrentFrame();
  const stamp = easeIn(frame, 38, 20);
  return (
    <AbsoluteFill style={{ background: coral, color: ink, fontFamily: sans }}>
      <div style={{ background: "#ffffff", border: `2px solid ${ink}`, borderRadius: 20, boxShadow: "0 22px 58px rgba(18,36,58,0.2)", height: 620, left: 80, overflow: "hidden", position: "absolute", top: 165, width: 910 }}>
        <Img src={staticFile("product-scenes/employment-no-path.png")} style={{ display: "block", height: "auto", width: "100%" }} />
      </div>
        <div style={{ background: lemon, border: `2px solid ${ink}`, borderRadius: 15, color: ink, fontFamily: mono, fontSize: 27, fontWeight: 800, left: 536, opacity: stamp, padding: "18px 25px", position: "absolute", top: 810, translate: `0px ${interpolate(frame, [38, 58], [16, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })}px` }}>
        NO_PATH · plan: null
      </div>
      <SceneCopy frame={frame} title="When evidence cannot answer, Sovra stops." body="Employment tenure is not age proof. The planner returns NO_PATH before guard, issuance or consent." top={225} width={650} titleSize={68} />
    </AbsoluteFill>
  );
};

const CloseScene = () => {
  const frame = useCurrentFrame();
  const trace = interpolate(frame, [8, 430], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const stages = [
    { title: "Ask", detail: "purpose-bound", fill: lemon },
    { title: "Map", detail: "guarded plan", fill: lilac },
    { title: "Consent", detail: "holder decides", fill: mint },
    { title: "Verify", detail: "issuer-bound", fill: coral },
  ];
  return (
    <AbsoluteFill style={{ background: cobalt, color: paper, fontFamily: sans }}>
      <div style={{ left: 74, position: "absolute", top: 250, width: 1070 }}>
        <div style={{ alignItems: "center", display: "flex", gap: 18 }}>
          {stages.map((stage, index) => {
            const opacity = easeIn(frame, 20 + index * 24, 18);
            return (
              <div key={stage.title} style={{ opacity, position: "relative" }}>
                <div style={{ background: stage.fill, border: `2px solid ${ink}`, borderRadius: 18, color: ink, height: 120, padding: "18px 20px", width: 222 }}>
                  <div style={{ fontFamily: display, fontSize: 35, fontWeight: 700 }}>{stage.title}</div>
                  <div style={{ color: muted, fontSize: 18, marginTop: 10 }}>{stage.detail}</div>
                </div>
                {index < stages.length - 1 && <div style={{ background: paper, height: 4, left: 224, opacity: trace, position: "absolute", top: 58, width: 35 }} />}
              </div>
            );
          })}
        </div>
        <div style={{ background: "rgba(255,255,255,0.14)", borderRadius: 14, color: paper, fontSize: 21, lineHeight: 1.45, marginTop: 34, maxWidth: 960, opacity: easeIn(frame, 120, 24), padding: "20px 24px" }}>
          A scoped signed credential is shown here — not a zero-knowledge proof.
        </div>
      </div>
      <SceneCopy frame={frame} title="Ask for one fact. Keep control visible." body="The planner proposes. A deterministic guard checks. The holder chooses. The issuer signs only for its own credential." top={205} width={620} dark titleSize={70} />
      <div style={{ bottom: 61, color: "#ffffff", fontFamily: sans, fontSize: 18, left: 84, position: "absolute", right: 80 }}>
        Synthetic local run · FIXTURE planner · live AI off · software vault KEK · no real identity data · production KMS/HSM and external conformance remain open
      </div>
    </AbsoluteFill>
  );
};

export const SovraThreeMinute = () => {
  const offsets = {
    problem: 0,
    apps: sceneFrames.problem,
    coreCompose: sceneFrames.problem + sceneFrames.apps,
    issuerCompose: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose,
    json: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose,
    holder: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json,
    recordedRun: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json + sceneFrames.holder,
    appOutcome: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json + sceneFrames.holder + sceneFrames.recordedRun,
    refusal: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json + sceneFrames.holder + sceneFrames.recordedRun + sceneFrames.appOutcome,
    encryption: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json + sceneFrames.holder + sceneFrames.recordedRun + sceneFrames.appOutcome + sceneFrames.refusal,
    close: sceneFrames.problem + sceneFrames.apps + sceneFrames.coreCompose + sceneFrames.issuerCompose + sceneFrames.json + sceneFrames.holder + sceneFrames.recordedRun + sceneFrames.appOutcome + sceneFrames.refusal + sceneFrames.encryption,
  };

  return (
    <Track name="Sovra product story · synthetic evidence">
      <Sequence name="The problem" durationInFrames={sceneFrames.problem}><ProblemScene /></Sequence>
      <Sequence name="Two relying-party apps" from={offsets.apps} durationInFrames={sceneFrames.apps}><AppsScene /></Sequence>
      <Sequence name="Core Compose stack" from={offsets.coreCompose} durationInFrames={sceneFrames.coreCompose}><CoreComposeScene /></Sequence>
      <Sequence name="Dual-issuer topology" from={offsets.issuerCompose} durationInFrames={sceneFrames.issuerCompose}><IssuerComposeScene /></Sequence>
      <Sequence name="Plan and guard JSON" from={offsets.json} durationInFrames={sceneFrames.json}><JsonScene /></Sequence>
      <Sequence name="Holder review" from={offsets.holder} durationInFrames={sceneFrames.holder}><HolderScene /></Sequence>
      <Sequence name="Recorded browser journey" from={offsets.recordedRun} durationInFrames={sceneFrames.recordedRun}><RecordedRunScene /></Sequence>
      <Sequence name="Two app outcomes" from={offsets.appOutcome} durationInFrames={sceneFrames.appOutcome}><AppOutcomeScene /></Sequence>
      <Sequence name="Fail-closed result" from={offsets.refusal} durationInFrames={sceneFrames.refusal}><RefusalScene /></Sequence>
      <Sequence name="Signing and vault encryption" from={offsets.encryption} durationInFrames={sceneFrames.encryption}><EncryptionScene /></Sequence>
      <Sequence name="What makes the flow different" from={offsets.close} durationInFrames={sceneFrames.close}><CloseScene /></Sequence>
    </Track>
  );
};

export const TOTAL_FRAMES =
  sceneFrames.problem +
  sceneFrames.apps +
  sceneFrames.coreCompose +
  sceneFrames.issuerCompose +
  sceneFrames.json +
  sceneFrames.holder +
  sceneFrames.recordedRun +
  sceneFrames.appOutcome +
  sceneFrames.encryption +
  sceneFrames.refusal +
  sceneFrames.close;
