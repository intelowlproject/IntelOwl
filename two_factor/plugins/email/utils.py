def mask_email(email):
    """
    Masks an email address, only first and last characters of the local part visible.

    Examples:

    * `j******e@example.com`
    * `t**@example.com`

    :param email: str
    :return: str
    """
    local_part, domain = email.split("@")
    local_part_length = len(local_part)

    if local_part_length < 4:
        masked_local_part = local_part[0] + "*" * (local_part_length - 1)
    else:
        masked_local_part = (
            local_part[0] + "*" * (local_part_length - 2) + local_part[-1]
        )

    return f"{masked_local_part}@{domain}"
