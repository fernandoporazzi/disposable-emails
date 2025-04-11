#ifndef RESPONSE_TYPES_HPP
#define RESPONSE_TYPES_HPP
enum class ResponseType {
    List = 1,
    Json,
};

enum class JsonResponseProcessor {
    Inboxes = 1,
    TempMailIo,
};
#endif //RESPONSE_TYPES_HPP
