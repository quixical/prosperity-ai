#version 330 core
// Two-texture cross-fade. fade=0 -> all current (A), fade=1 -> all next (B).
// Output alpha is forced opaque; uncovered areas are handled by the black clear.

uniform sampler2D texA;
uniform sampler2D texB;
uniform float fade;

in vec2 v_uvA;
in vec2 v_uvB;

out vec4 f_color;

void main() {
    vec3 a = texture(texA, v_uvA).rgb;
    vec3 b = texture(texB, v_uvB).rgb;
    f_color = vec4(mix(a, b, fade), 1.0);
}
