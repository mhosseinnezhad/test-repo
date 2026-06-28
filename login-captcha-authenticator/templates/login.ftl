<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=social.displayInfo;  section>
    <#if section = "title">
        ${msg("loginTitle",(realm.displayName!''))}
    <#elseif section = "header">
        <link href="${url.resourcesPath}/img/favicon.png" rel="icon"/>
        <script>
            function togglePassword() {
                var x = document.getElementById("password");
                var v = document.getElementById("vi");
                if (x.type === "password") {
                    x.type = "text";
                    v.src = "${url.resourcesPath}/img/eye.png";
                } else {
                    x.type = "password";
                    v.src = "${url.resourcesPath}/img/eye-off.png";
                }
            }

           $(function() {
                $("#renewCaptcha").click(reloadCaptcha);              
                reloadCaptcha();
            });
    	    function reloadCaptcha() {
                $.ajax({
                    url: "/auth/realms/abis-ui/gaurav-rest/newCaptcha", 
                    type: "GET",
                    dataType: 'text',
                    success: function( data ) {
                        $( "#captcha_img" ).attr('src', data);
                    }
                });                
            }
        </script>

    <#elseif section = "form">
        <div>
            <img class="logo" src="${url.resourcesPath}/img/misc-logo.png" alt="MISC">
        </div>

        <div class="box-container">
            <div>
                <p class="application-name">${msg("title")}</p>
            </div>
        <#if realm.password>
            <div>
               <form id="kc-form-login" class="form" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post" >
                    <input id="username" class="login-field" placeholder="${msg("username")}" type="text" name="username" tabindex="1">
                    <#--  <div>
                        <label class="visibility" id="v" onclick="togglePassword()"><img id="vi" src="${url.resourcesPath}/img/eye-off.png"></label>
                    </div>  -->
                    <br><br>
                    <input id="password" class="login-field" placeholder="${msg("password")}" type="password" name="password" tabindex="2" autocomplete="off">
                <br><br>
                <img  id="captcha_img" class="captcha_img">
                <input type="button" id="renewCaptcha" style="background-image: url(${url.resourcesPath}/img/refresh.png);background-size:100% 100%;">
                <input id="captcha" class="login-field" type="text" name="givenCaptcha" tabindex="3" placeholder="${msg("captcha")}">
                <input class="submit" type="submit" value="${msg("doLogIn")}" tabindex="4">
              </form>
            </div>
        </#if>
        <#if social.providers??>
            <p class="para">${msg("selectAlternative")}</p>
            <div id="social-providers">
                <#list social.providers as p>
                <input class="social-link-style" type="button" onclick="location.href='${p.loginUrl}';" value="${p.displayName}"/>
                </#list>
            </div>
        </#if>      
        <div>
            <#--  <p class="copyright">&copy; ${msg("copyright", "${.now?string('yyyy')}")}</p>  -->
            <p></p>
        </div>
    </#if>
</@layout.registrationLayout>
