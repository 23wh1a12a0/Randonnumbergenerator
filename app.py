from flask import Flask, render_template, request
import secrets
import string
import math

app = Flask(__name__)

def check_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if any(c.islower() for c in password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        suggestions.append("Add special characters.")

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, suggestions


def generate_password(length, use_upper, use_lower,
                      use_digits, use_symbols):
    groups = []

    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append(string.punctuation)

    if not groups:
        raise ValueError("Select at least one character type.")

    if length < len(groups):
        raise ValueError("Length is too short for selected types.")

    # Ensure at least one character from each selected group.
    password_chars = [
        secrets.choice(group) for group in groups
    ]
    all_chars = "".join(groups)

    password_chars.extend(
        secrets.choice(all_chars)
        for _ in range(length - len(password_chars))
    )

    # Securely shuffle the characters.
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


@app.route("/", methods=["GET", "POST"])
def home():
    generated = ""
    strength = ""
    suggestions = []
    checked_password = ""
    error = ""

    if request.method == "POST":
        action = request.form.get("action")

        try:
            if action == "generate":
                length = int(request.form.get("length", 16))

                if not 8 <= length <= 64:
                    raise ValueError(
                        "Password length must be between 8 and 64."
                    )

                generated = generate_password(
                    length,
                    "upper" in request.form,
                    "lower" in request.form,
                    "digits" in request.form,
                    "symbols" in request.form
                )

                strength, suggestions = check_strength(generated)

            elif action == "check":
                checked_password = request.form.get(
                    "password", ""
                )

                if not checked_password:
                    raise ValueError("Enter a password to check.")

                strength, suggestions = check_strength(
                    checked_password
                )

        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        generated=generated,
        strength=strength,
        suggestions=suggestions,
        checked_password=checked_password,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)
