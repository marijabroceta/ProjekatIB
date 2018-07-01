$(document).ready(function(){
	$('#submit_add').on('click',function(e){
		addUser();
		
		e.preventDefault();
		return false;
	});

});

function addUser(){
	console.log("submit");
	var email = $('#email_txt').val().trim();
	var password = $('#password_txt').val().trim();
	
	var data = {
			'email':email,
			'password':password
		}
		console.log(data);
		$.ajax({
				type: 'POST',
		        contentType: 'application/json',
		        
		        url: 'https://localhost:8443/api/users/save',
		        data: JSON.stringify(data),
		        dataType: 'json',
		        crossDomain: true,
				cache: false,
				processData: false,
				success:function(response){
					alert("Created");
					window.location.replace("https://localhost:8443/");
				},
				error: function (jqXHR, textStatus, errorThrown) {
					console.log(jqXHR);
					alert(textStatus);
				}
		});
}