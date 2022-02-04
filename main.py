import random
#
# aliens = []
# colors = ['red', 'green', 'blue', 'yellow']
#
# speeds = ['slow', 'medium', 'fast']
#
# for i in range(0, 25):
#     alien = {}
#     points = random.randint(0, 100)
#     color_int = random.randint(0, 3)
#     speed = random.randint(0, 2)
#     alien['color'] = colors[color_int]
#     alien['points'] = points
#     alien['speed'] = speeds[speed]
#     # print(f'{i + 1}. {alien}')
#     aliens.append(alien)
#
# for i, alien in enumerate(aliens[:5]):
#     print(i + 1)
#     for key, value in alien.items():
#         print(f'{key}: {value}')
#     print("-" * 30)
#
# print(f'Total number of aliens: {len(aliens)}')

favorite_languages = {
    'jen': ['python', 'ruby'],
    'sarah': ['c'],
    'edward': ['ruby', 'go'],
    'phil': ['python', 'haskell'],
    }

for name, languages in favorite_languages.items():
    if len(languages) == 1:
        print(f"\n{name.title()}'s favorite languages are: {languages[0].title()}")
    else:
        print(f"\n{name.title()}'s favorite languages are:")
        for language in languages:
            print(f"\t{language.title()}")