from aiohttp.client_exceptions import ClientResponseError

class EnrichedClientResponseError(ClientResponseError):
    def __init__(self, origional_error, text, json):
        super().__init__(request_info=origional_error.request_info,
                history=origional_error.history,
                status=origional_error.status,
                message=origional_error.message,
                headers=origional_error.headers)

        self.text = text
        self.json = json
        
