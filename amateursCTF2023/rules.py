# # __RULES__
# 107122414347637. Use common sense.
# 125839376402043. Play nice. No interfering with other competitors or infrastructure, and keep brute forcing to a minimum.
# 122524418662265. Do not attack other infrastructure or organizers. Any service running on the domain `amt.rs` is in scope. Keep brute forcing to a minimum.
# 122549902405493. Admins reserve the right to modify the rules at any point (mostly to clarify things).
# 121377376789885. PLEASE DO NOT COMMUNICATE WITH ADMINS THROUGH DMS, **USE THE MODMAIL/TICKET BOT INSTEAD**
# Good job for reading the rules. Here's your sanity check flag: `amateursCTF{be_honest._did_you_actually_read_the_rules?}`
# ## vv anything in the red box is disallowed (yes that means flag hoarding is banned)

# parsing

num = [107122414347637,
125839376402043,
122524418662265,
122549902405493,
121377376789885]

from Crypto.Util.number import long_to_bytes as l2b

print(b''.join([l2b(i) for i in num]))