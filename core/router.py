from rest_framework.routers import SimpleRouter


class OptionalSlashRouter(SimpleRouter):

    def _init_(self):
        super()._init_()
        self.trailing_slash = '/?'
