$.get("/user", function(data) {
    $("#user").html(data.name);
    $(".unauthenticated").hide()
    $(".authenticated").show()
});

// $.get("/error", function(data) {
//     if (data) {
//         $(".error").html("works");
//     } else {
//         $(".error").html('');
//     }
// });



