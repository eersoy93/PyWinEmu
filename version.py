class Version:
    def get_project_name():
        with open("PROJECT_NAME", "r") as f:
            PROJECT_NAME = f.readline().strip()
            return PROJECT_NAME

    def get_version():
        with open("VERSION", "r") as f:
            PROJECT_VERSION = f.readline().strip()
            return PROJECT_VERSION
