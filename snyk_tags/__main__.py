# snyk_tags/__main__.py

from snyk_tags import cli, __app_name__, tags

def main():
    tags.app(prog_name=__app_name__)

if __name__ == "__main__":
    main()