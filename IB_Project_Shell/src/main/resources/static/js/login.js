$(document).ready(function(){

	var submit = $('#submit');

	$('#cancel').on('click',function(e){
		$('#add_form').hide();
		e.preventDefault();
		return false;
	});

	submit.on('click',function(e) {
		login();
		
		e.preventDefault();
		return false;
	});
	
	
});

function login(){
	var email = $('#email').val().trim();
	var password = $('#password').val().trim();
	var token = '';

	var data = {
		'username':email,
		'password':password
	}
	console.log(data);

	$.ajax({
		type: 'POST',
        contentType: 'application/json',
        url: 'https://localhost:8443/api/auth/login',
        data: JSON.stringify(data),
        dataType: 'json',
        crossDomain: true,
		cache: false,
		processData: false,
		success:function(response){
			var token = response.access_token;
			console.log(token);
			console.log(response);
			
			localStorage.setItem("token",token);
			window.location.href = "main_page.html";
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus);
		}
	});
}

