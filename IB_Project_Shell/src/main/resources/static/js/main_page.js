$(document).ready(function(){
	var user_id = 0;
	
	var token = localStorage.getItem("token");
	console.log(token);
	var logged = null;
	var activate_user = $('#activate_user');
	
	activate_user.hide();
	
	$('#logout').on('click',function(e){
		localStorage.removeItem("token");
		window.location.replace("https://localhost:8443/");
	});
	
	$.ajax({
		url: "https://localhost:8443/api/users/logged",
		type: 'GET',
		headers: { "Authorization": "Bearer " + token},
		contentType : "application/json",
		dataType:'json',
		crossDomain: true,
		success : function(response) {
			
			console.log("logged " + response.authorities[0].name);
			logged = response;
			if(logged.authorities[0].name == "ADMIN"){
				getAllUsers(token);
				activate_user.show();
				activate_user.on('click',function(e){
					$.ajax({
						headers:{"Authorization" :"Bearer " + token},
						contentType: 'application/json',
						type: 'GET',
						dataType:'json',
						crossDomain: true,
						url:'https://localhost:8443/api/users/inactive',
						success:function(response){
							table_header_inactive();
							var table = $('#users_inactive');
							for(var i=0; i<response.length; i++) {
								user = response[i];
								console.log(user);
								table.append('<tr class="data">'+
												'<td>'+user.email+'</td>'+
												'<td>'+user.active+'</td>'+
												'<td><button id="activate_btn" onclick="activate_users(' + user.id + ')" class="btn btn-default">Activate</button></td>'+
											'</tr>');
							}
						}
					});
				});
			}else{
				getAllActive(token);
			}
		},
		error: function (jqXHR, textStatus, errorThrown) { 
			console.log(jqXHR.status);
			console.log(jqXHR);
			
		}
	});

	
	
	
});

function getAllUsers(token){
	$.ajax({
			
			headers:{"Authorization" :"Bearer " + token
				},
			contentType: 'application/json',
			type: 'GET',
			dataType:'json',
			crossDomain: true,
			url:'https://localhost:8443/api/users',
			success:function(response){
				table_header();
				var table = $('#users_table');
				for(var i=0; i<response.length; i++) {
					user = response[i];
					
					console.log(user);
					table.append('<tr class="data">'+
									'<td>'+user.email+'</td>'+
									'<td>'+user.authorities[0].name+'</td>'+
									'<td>'+user.active+'</td>'+
									'<td><button class="btn btn-default">Download</button></td>'+
								'</tr>');
				}
			},
			error: function (jqXHR, textStatus, errorThrown) { 
				console.log(jqXHR);
				alert(textStatus);
			}
		});
}

function getAllActive(token){
	$.ajax({
		
		headers:{"Authorization" :"Bearer " + token
			},
		contentType: 'application/json',
		type: 'GET',
		dataType:'json',
		crossDomain: true,
		url:'https://localhost:8443/api/users/active',
		success:function(response){
			table_header();
			var table = $('#users_table');
			for(var i=0; i<response.length; i++) {
				user = response[i];
				
				console.log(user);
				table.append('<tr class="data">'+
								'<td>'+user.email+'</td>'+
								'<td>'+user.authorities[0].name+'</td>'+
								'<td>'+user.active+'</td>'+
								'<td><button class="btn btn-default">Download</button></td>'+
							'</tr>');
			}
		},
		error: function (jqXHR, textStatus, errorThrown) { 
			console.log(jqXHR);
			alert(textStatus);
		}
	});
}

function table_header(){
	var table = $('#users_table');
	table.empty();
	table.append('<tr>'+
					'<th>Email</th>'+
					'<th>Role</th>'+
					'<th>Active</th>'+
					'<th>Certificate</th>'+
				'</tr>');
}

function table_header_inactive(){
	var table = $('#users_inactive');
	table.empty();
	table.append('<tr>'+
					'<th>Email</th>'+
					'<th>Active</th>'+
					
				'</tr>');
}

function activate_users(id){
	var token = localStorage.getItem("token");
	user_id = id;
	console.log(user_id);
	$.ajax({
		type: 'PUT',
        contentType: 'application/json',
        headers:{"Authorization" :"Bearer " + token},
  
        url: 'https://localhost:8443/api/users/' + id,
        dataType: 'json',
        crossDomain: true,
		cache: false,
		processData: false,
		success:function(response){
			alert("Activated");
			location.reload();
		},
		error: function (jqXHR, textStatus, errorThrown) {
			console.log(jqXHR);
			alert(textStatus);
		}
	});
}

function search(){
	var search = $('#search').val().trim();
	var token = localStorage.getItem("token");
	
	$.ajax({
			type:'GET',
			contentType: 'application/json',
	        headers:{"Authorization" :"Bearer " + token},
	  
	        url: 'https://localhost:8443/api/users/search/' + search,
	        dataType: 'json',
	        crossDomain: true,
			cache: false,
			processData: false,
			success:function(response){
				table_header();
				
				var table = $('#users_table');
				for(var i=0; i<response.length; i++) {
					
					user = response[i];
					
					table.append('<tr class="data">'+
									'<td>'+user.email+'</td>'+
									'<td>'+user.authorities[0].name+'</td>'+
									'<td><button class="btn btn-default">Download</button></td>'+
								'</tr>');
				}
			},
			error: function (jqXHR, textStatus, errorThrown) {
				console.log(jqXHR);
				alert(textStatus);
			}
			
	});
	
}

function get_users(){
	
}
