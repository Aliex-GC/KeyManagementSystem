import math
def calculate_charset_length( password):
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        charset_length = 0
        if has_lower:
            charset_length += 26
        if has_upper:
            charset_length += 26
        if has_digit:
            charset_length += 10
        if has_special:
            charset_length += 32  # Assuming 32 common special characters

        return charset_length

def calculate_entropy(  password):
        charset_length =  calculate_charset_length(password)
        password_length = len(password)
        entropy = password_length * math.log2(charset_length)
        return entropy

def estimate_crack_time(  entropy):
        # Assume 10 billion guesses per second
        guesses_per_second = 10**10
        total_guesses = 2**entropy
        seconds = total_guesses / guesses_per_second
        return seconds

def human_readable_time(  seconds):
        intervals = [
            ('year', 60 * 60 * 24 * 365),
            ('month', 60 * 60 * 24 * 30),
            ('day', 60 * 60 * 24),
            ('hour', 60 * 60),
            ('minute', 60),
            ('second', 1)
        ]

        result = []
        for name, count in intervals:
            value = seconds // count
            if value:
                seconds -= value * count
                result.append(f"{int(value)} {name}{'s' if value > 1 else ''}")
        
        return ', '.join(result) or 'less than a second'

def password_strength_score(  entropy):
        # Normalizing the entropy to a score between 0 and 1
        max_entropy = 128  # Assuming a max entropy for very strong passwords
        score = min(entropy / max_entropy, 1)
        return score

def analyze_password(password):
        charset_length =calculate_charset_length(password)
        entropy = calculate_entropy(password)
        crack_time = estimate_crack_time(entropy)
        human_time = human_readable_time(crack_time)
        strength_score =  password_strength_score(entropy)

        return {
            "charset_length": charset_length,
            "entropy": entropy,
            "crack_time_seconds": crack_time,
            "human_readable_crack_time": human_time,
            "strength_score": strength_score
        }