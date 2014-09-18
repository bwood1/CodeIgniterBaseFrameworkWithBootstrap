var pathArray = document.URL.split('/');

localStorage.domain = 'http://' + pathArray[2];
//localStorage.path = '/ss/request.php?';
localStorage.path = '/brandon/housing/php/request.php?';

localStorage.loginRequest = 'request=login';
localStorage.submitRequest = 'request=submit';
localStorage.approveRequest = 'request=approve';
localStorage.somethingRequest = 'request=something';
