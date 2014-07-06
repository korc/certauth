"use strict";
function rigNewForm(form) {
  var inp=form.querySelector("input[name=resource]");
  var uaRe=/(Linux).*(Firefox|Chrome)/;
  var m=window.navigator.userAgent.match(uaRe);
  inp.value=m?(m[1]+" "+m[2]):window.navigator.userAgent;
  var unameInput=document.body.querySelector("input[name=uname]");
  form.addEventListener("submit", function(ev) {
    var userNameInput=this.querySelector("input[name=uname]");
    if(!userNameInput.value) {
      alert("Please enter username");
      userNameInput.focus();
      ev.stopPropagation();
      ev.preventDefault();
      return false;
    }
  }, true);
}

function populateReqDiv(div, data) {
  var ul=document.createElement("ul");
  data.forEach(function(e) {
    var li=document.createElement("li");
    if(e.have_cert) {
      var link=document.createElement("a");
      link.setAttribute("href", "cert/"+e.req_id);
      link.appendChild(document.createTextNode("[dl]"));
      li.appendChild(link);
    }
    for(var name in e) {
      li.appendChild(document.createTextNode(name+": "));
      li.appendChild(document.createTextNode(e[name]));
      li.appendChild(document.createElement("br"));
    }
    ul.appendChild(li);
  });
  div.appendChild(ul);
}

window.addEventListener("load", function() {
  var xhr=new XMLHttpRequest();
  xhr.open("get", "req", true);
  xhr.responseType="json";
  xhr.addEventListener("load", function(ev) {
    var form=document.body.querySelector("#newform");
    var reqDiv=document.body.querySelector("#req");
    if(this.response&&this.response.length) {
      form.style.display="none";
      populateReqDiv(reqDiv, this.response);
    } else {
      form.style.display=null;
      rigNewForm(form);
    }
    console.log("req", this);
  }, false);
  xhr.send();
  ;
}, false);
