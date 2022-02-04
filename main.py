from typing import Dict, Any

users = []


def add_user(user_name: str, user_age: int = 23) -> dict:
    user: Dict[str, int] = {'user_name': user_name,
            'user_age': user_age
            }
    return user


message = "Input Name and Age of added person: "
text = ''
while 'q' not in text:
    user = {}
    text = input(message)
    if 'q' in text:
        break
    name, age = text.split(' ')[0], int(text.split(' ')[1])
    users.append(add_user(name, age))

print(users)
