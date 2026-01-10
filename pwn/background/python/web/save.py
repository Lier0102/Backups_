import urllib.request

# vro got blocked
def get_page(page):
    print(f"page:{page}")
    rsrc = f"https://namu.wiki/w/{page}"
    with urllib.request.urlopen(rsrc) as r:
        with open(f'namuwiki_{page}.html', 'wb') as f:
            fwrite(r.read())


get_page("asdf")
