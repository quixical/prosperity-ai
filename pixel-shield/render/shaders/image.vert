#version 330 core
// Per-monitor quad. Positions are already in NDC; UVs are precomputed on the CPU
// (cover-fit + micro-shift window + per-monitor canvas slice) for each of the two
// cross-fading images. v is top-down to match texture upload (row 0 = top).

in vec2 in_pos;
in vec2 in_uvA;
in vec2 in_uvB;

out vec2 v_uvA;
out vec2 v_uvB;

void main() {
    v_uvA = in_uvA;
    v_uvB = in_uvB;
    gl_Position = vec4(in_pos, 0.0, 1.0);
}
