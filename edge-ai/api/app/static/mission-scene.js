/* Illustrative 3D motion, not geographic attack telemetry. */
(() => {
  const canvas = document.getElementById("defenseCanvas");
  const host = document.getElementById("scene");
  const button = document.getElementById("motionToggle");
  const mode = document.getElementById("sceneMode");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let paused = false,
    disposed = false,
    suspended = false;
  let inView = true,
    contextLost = false,
    frame = 0,
    last = 0,
    elapsed = 0;
  let renderer;
  const unavailable = () => {
    canvas.hidden = true;
    button.disabled = true;
    button.textContent = "Animation unavailable";
    button.title = "WebGL is unavailable; the 3D artwork remains visible.";
    mode.textContent = "3D artwork · static fallback";
  };
  try {
    if (!window.THREE) throw new Error("Three.js unavailable");
    renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
      powerPreference: "low-power",
    });
  } catch (_) {
    unavailable();
    return;
  }
  canvas.dataset.renderer = "threejs";
  canvas.dataset.frames = "0";
  renderer.setClearColor(0x000000, 0);
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));

  // One coordinate system follows the image's object-fit:contain at every size.
  const imageAspect = 1448 / 1086;
  const scene = new THREE.Scene();
  const camera = new THREE.OrthographicCamera(-1, 1, 0.5, -0.5, 0.01, 10);
  camera.position.z = 3;
  const field = new THREE.Group();
  scene.add(field);
  const at = (u, v, z = 0) =>
    new THREE.Vector3((u - 0.5) * imageAspect, 0.5 - v, z);
  const blend = {
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: false,
  };

  const glowCanvas = document.createElement("canvas");
  glowCanvas.width = glowCanvas.height = 64;
  const context = glowCanvas.getContext("2d");
  if (!context) {
    renderer.dispose();
    unavailable();
    return;
  }
  const gradient = context.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, "rgba(255,255,255,1)");
  gradient.addColorStop(0.16, "rgba(255,255,255,.85)");
  gradient.addColorStop(0.45, "rgba(255,255,255,.22)");
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  context.fillStyle = gradient;
  context.fillRect(0, 0, 64, 64);
  const texture = new THREE.CanvasTexture(glowCanvas);
  const glow = (color, size, opacity = 1) => {
    const sprite = new THREE.Sprite(
      new THREE.SpriteMaterial({ map: texture, color, opacity, ...blend }),
    );
    sprite.scale.set(size, size, 1);
    field.add(sprite);
    return sprite;
  };

  // Segmented, rotating rings around the shield base. Gaps make rotation legible.
  const base = new THREE.Group();
  base.position.copy(at(0.5, 0.825, 0.04));
  base.rotation.x = 1.15;
  field.add(base);
  const arcs = [];
  for (let i = 0; i < 3; i++) {
    const arc = new THREE.Mesh(
      new THREE.TorusGeometry(0.19 + i * 0.038, 0.0025, 6, 100, Math.PI * 1.45),
      new THREE.MeshBasicMaterial({
        color: i === 1 ? 0xc4f7ff : 0x19caff,
        opacity: 0.82,
        ...blend,
      }),
    );
    arc.rotation.z = i * 2;
    base.add(arc);
    arcs.push(arc);
  }
  const shieldGlow = glow(0x05adff, 0.32, 0.24);
  shieldGlow.position.copy(at(0.5, 0.66, 0.03));

  const beacons = [
    [0.138, 0.305],
    [0.255, 0.295],
    [0.51, 0.26],
    [0.767, 0.34],
    [0.862, 0.312],
    [0.873, 0.558],
  ];
  const routes = beacons.map(([u, v], index) => {
    const start = at(u, v, 0.02),
      end = at(0.5, 0.57, 0.03);
    const curve = new THREE.QuadraticBezierCurve3(
      start,
      at((u + 0.5) / 2, Math.min(v, 0.3) - 0.06, 0.14),
      end,
    );
    const geometry = new THREE.BufferGeometry().setFromPoints(
      curve.getPoints(72),
    );
    const color = index % 2 ? 0x30d7ff : 0xff435d;
    const line = new THREE.Line(
      geometry,
      new THREE.LineBasicMaterial({ color, opacity: 0.32, ...blend }),
    );
    field.add(line);
    const trail = Array.from({ length: 8 }, (_, i) =>
      glow(color, 0.026 - i * 0.0017, 0.95 - i * 0.105),
    );
    const pulse = new THREE.Mesh(
      new THREE.RingGeometry(0.012, 0.014, 40),
      new THREE.MeshBasicMaterial({
        color,
        opacity: 0.9,
        side: THREE.DoubleSide,
        ...blend,
      }),
    );
    pulse.position.copy(start);
    field.add(pulse);
    return { curve, trail, pulse, index };
  });
  const scan = new THREE.Mesh(
    new THREE.PlaneGeometry(imageAspect * 0.94, 0.0025),
    new THREE.MeshBasicMaterial({ color: 0x68e5ff, opacity: 0.48, ...blend }),
  );
  const scanGlow = new THREE.Mesh(
    new THREE.PlaneGeometry(imageAspect * 0.94, 0.035),
    new THREE.MeshBasicMaterial({ color: 0x0088c9, opacity: 0.08, ...blend }),
  );
  scan.position.z = scanGlow.position.z = 0.01;
  field.add(scan, scanGlow);
  const dustGeometry = new THREE.BufferGeometry();
  const dust = new Float32Array(80 * 3);
  for (let i = 0; i < 80; i++) {
    dust[i * 3] = Math.sin(i * 137.5) * 0.58;
    dust[i * 3 + 1] = Math.cos(i * 76.1) * 0.37;
    dust[i * 3 + 2] = 0.02;
  }
  dustGeometry.setAttribute("position", new THREE.BufferAttribute(dust, 3));
  const stars = new THREE.Points(
    dustGeometry,
    new THREE.PointsMaterial({
      color: 0x6bdbff,
      size: 0.0016,
      opacity: 0.6,
      ...blend,
    }),
  );
  field.add(stars);

  function draw(time) {
    arcs.forEach(
      (arc, i) =>
        (arc.rotation.z = (i % 2 ? -1 : 1) * time * (0.7 + i * 0.18) + i * 2),
    );
    shieldGlow.material.opacity = 0.16 + Math.sin(time * 2.4) * 0.08;
    routes.forEach(({ curve, trail, pulse, index }) => {
      const phase = (time * 0.26 + index / 6) % 1;
      trail.forEach((sprite, i) =>
        sprite.position.copy(curve.getPoint((phase - i * 0.014 + 1) % 1)),
      );
      const wave = (time * 0.65 + index / 6) % 1;
      pulse.scale.setScalar(1 + wave * 3.5);
      pulse.material.opacity = (1 - wave) * 0.9;
    });
    scan.position.y = scanGlow.position.y = 0.41 - ((time * 0.16) % 0.59);
    stars.rotation.z = Math.sin(time * 0.15) * 0.015;
    renderer.render(scene, camera);
  }
  function resize() {
    const w = host.clientWidth,
      h = host.clientHeight;
    if (!w || !h || disposed) return;
    renderer.setSize(w, h, false);
    camera.left = -w / h / 2;
    camera.right = w / h / 2;
    camera.updateProjectionMatrix();
    field.scale.setScalar(Math.min(1, w / h / imageAspect));
    draw(elapsed);
  }
  function label() {
    button.textContent = paused ? "Play animation" : "Pause animation";
    button.setAttribute("aria-pressed", String(paused));
    canvas.dataset.paused = String(paused);
    mode.textContent = paused
      ? "Three.js · paused"
      : "Three.js · animated threat paths";
  }
  function stop() {
    cancelAnimationFrame(frame);
    frame = 0;
    last = 0;
  }
  function active() {
    return (
      !disposed &&
      !paused &&
      !suspended &&
      !contextLost &&
      inView &&
      !document.hidden
    );
  }
  function tick(timestamp) {
    frame = 0;
    if (!active()) return;
    if (!last) last = timestamp;
    if (timestamp - last >= 33) {
      elapsed += Math.min((timestamp - last) / 1000, 0.1) * (reduced.matches ? 0.35 : 1);
      last = timestamp;
      draw(elapsed);
      canvas.dataset.frames = String(Number(canvas.dataset.frames) + 1);
    }
    frame = requestAnimationFrame(tick);
  }
  function start() {
    if (active() && !frame) {
      last = 0;
      frame = requestAnimationFrame(tick);
    }
  }
  function synchronize() {
    stop();
    start();
  }
  const observer = new ResizeObserver(resize);
  observer.observe(host);
  const intersection = new IntersectionObserver((entries) => {
    inView = entries[0].isIntersecting;
    synchronize();
  });
  intersection.observe(host);
  button.addEventListener("click", () => {
    if (disposed || contextLost) return;
    paused = !paused;
    label();
    synchronize();
  });
  reduced.addEventListener("change", () => {
    synchronize();
  });
  document.addEventListener("visibilitychange", synchronize);
  // BFCache keeps the DOM and handlers: preserve GPU resources and restart RAF.
  window.addEventListener("pagehide", (event) => {
    suspended = true;
    stop();
    if (event.persisted) return;
    disposed = true;
    observer.disconnect();
    intersection.disconnect();
    const geometries = new Set(),
      materials = new Set();
    scene.traverse((object) => {
      if (object.geometry) geometries.add(object.geometry);
      if (object.material) materials.add(object.material);
    });
    geometries.forEach((g) => g.dispose());
    materials.forEach((m) => m.dispose());
    texture.dispose();
    renderer.dispose();
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted && !disposed) {
      suspended = false;
      resize();
      synchronize();
    }
  });
  canvas.addEventListener("webglcontextlost", (event) => {
    event.preventDefault();
    contextLost = true;
    stop();
    unavailable();
  });
  canvas.addEventListener("webglcontextrestored", () => {
    contextLost = false;
    canvas.hidden = false;
    button.disabled = false;
    label();
    resize();
    start();
  });
  label();
  resize();
  start();
})();
