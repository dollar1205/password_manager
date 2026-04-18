from __future__ import annotations

from PySide6.QtCore import QEasingCurve, Property, QParallelAnimationGroup, QPropertyAnimation, QRect
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QWidget


class AnimatedShadowEffect(QGraphicsDropShadowEffect):
    def __init__(self, color: QColor, blur_radius: float, y_offset: float = 10.0):
        super().__init__()
        self.setColor(color)
        self.setBlurRadius(blur_radius)
        self.setOffset(0.0, y_offset)

    def get_blur_radius(self) -> float:
        return float(self.blurRadius())

    def set_blur_radius(self, value: float) -> None:
        self.setBlurRadius(value)

    blurRadiusAnimated = Property(float, get_blur_radius, set_blur_radius)


def attach_shadow(
    widget: QWidget,
    *,
    color: str = "#0b102020",
    blur_radius: float = 36.0,
    y_offset: float = 12.0,
) -> AnimatedShadowEffect:
    effect = widget.graphicsEffect()
    if isinstance(effect, AnimatedShadowEffect):
        return effect

    shadow = AnimatedShadowEffect(QColor(color), blur_radius, y_offset)
    widget.setGraphicsEffect(shadow)
    return shadow


def animate_shadow(
    widget: QWidget,
    *,
    start_blur: float,
    end_blur: float,
    duration: int = 180,
) -> QPropertyAnimation:
    shadow = attach_shadow(widget)
    animation = QPropertyAnimation(shadow, b"blurRadiusAnimated", widget)
    animation.setDuration(duration)
    animation.setStartValue(start_blur)
    animation.setEndValue(end_blur)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.start()
    return animation


def animate_widget_opacity(
    widget: QWidget,
    *,
    start: float = 0.82,
    end: float = 1.0,
    duration: int = 220,
) -> QPropertyAnimation:
    effect = widget.graphicsEffect()
    if not isinstance(effect, QGraphicsOpacityEffect):
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)

    effect.setOpacity(start)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(start)
    animation.setEndValue(end)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.start()
    return animation


def animate_window_pop(widget: QWidget, *, duration: int = 210) -> QParallelAnimationGroup:
    original_geometry = widget.geometry()
    inset_x = max(6, original_geometry.width() // 80)
    inset_y = max(6, original_geometry.height() // 80)
    smaller_geometry = QRect(
        original_geometry.x() + inset_x,
        original_geometry.y() + inset_y,
        max(1, original_geometry.width() - inset_x * 2),
        max(1, original_geometry.height() - inset_y * 2),
    )

    geometry_animation = QPropertyAnimation(widget, b"geometry", widget)
    geometry_animation.setDuration(duration)
    geometry_animation.setStartValue(smaller_geometry)
    geometry_animation.setEndValue(original_geometry)
    geometry_animation.setEasingCurve(QEasingCurve.Type.OutBack)

    widget.setWindowOpacity(0.0)
    opacity_animation = QPropertyAnimation(widget, b"windowOpacity", widget)
    opacity_animation.setDuration(duration)
    opacity_animation.setStartValue(0.0)
    opacity_animation.setEndValue(1.0)
    opacity_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    group = QParallelAnimationGroup(widget)
    group.addAnimation(geometry_animation)
    group.addAnimation(opacity_animation)
    group.start()
    return group
