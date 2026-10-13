from PIL import Image, ImageDraw

def create_shield_icon(color: str, symbol: str = "") -> Image.Image:
    """
    Generates a 64x64 RGBA shield icon dynamically.
    color: '#28a745' (green), '#007acc' (blue), '#dc3545' (red), '#ffc107' (yellow)
    """
    size = (64, 64)
    image = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Shield polygon coordinates
    points = [
        (32, 4),   # top center
        (56, 12),  # top right
        (52, 42),  # lower right curve
        (32, 60),  # bottom tip
        (12, 42),  # lower left curve
        (8, 12),   # top left
    ]

    # Draw shadow / outer border
    shadow_points = [(x + 1, y + 1) for (x, y) in points]
    draw.polygon(shadow_points, fill=(20, 20, 20, 100))

    # Draw shield body
    draw.polygon(points, fill=color)

    # Inner highlight / border
    inner_points = [
        (32, 8),
        (52, 15),
        (48, 40),
        (32, 54),
        (16, 40),
        (12, 15),
    ]
    draw.polygon(inner_points, outline=(255, 255, 255, 140), width=2)

    # Symbols inside
    if symbol == "check":
        # Green check mark
        draw.line([(22, 32), (29, 39), (42, 23)], fill=(255, 255, 255, 255), width=4)
    elif symbol == "cross":
        # Red cross / exclamation
        draw.line([(24, 22), (40, 38)], fill=(255, 255, 255, 255), width=4)
        draw.line([(40, 22), (24, 38)], fill=(255, 255, 255, 255), width=4)
    elif symbol == "scan":
        # Search / radar circle
        draw.ellipse([24, 22, 40, 38], outline=(255, 255, 255, 255), width=3)
        draw.line([(37, 35), (44, 42)], fill=(255, 255, 255, 255), width=3)
    elif symbol == "refresh":
        # Arrows / update circle
        draw.arc([23, 21, 41, 39], start=30, end=300, fill=(255, 255, 255, 255), width=3)
        draw.polygon([(40, 20), (45, 27), (35, 27)], fill=(255, 255, 255, 255))

    return image

class IconFactory:
    _icons = {}

    @classmethod
    def get_icon(cls, state: str) -> Image.Image:
        """
        Returns cached icon image for state:
        'idle' | 'scanning' | 'updating' | 'threat'
        """
        if state not in cls._icons:
            if state == "idle":
                cls._icons[state] = create_shield_icon("#1e7e34", "check")
            elif state == "scanning":
                cls._icons[state] = create_shield_icon("#0069d9", "scan")
            elif state == "updating":
                cls._icons[state] = create_shield_icon("#17a2b8", "refresh")
            elif state == "threat":
                cls._icons[state] = create_shield_icon("#bd2130", "cross")
            else:
                cls._icons[state] = create_shield_icon("#6c757d")
        return cls._icons[state]
