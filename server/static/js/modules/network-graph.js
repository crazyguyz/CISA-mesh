/**
 * GIAM-SAT Dashboard - Neural Network Graph (v1.12.0)
 * Uses window globals: drawNetworkGraph, networkGraphNodes, selectMachine
 */

// Graph state (global)
window.networkGraphNodes = [];
var _ng_zoom = 1.0;
var _ng_offsetX = 0;
var _ng_offsetY = 0;
var _ng_dragging = false;
var _ng_dragStartX = 0;
var _ng_dragStartY = 0;
var _ng_dragOffX = 0;
var _ng_dragOffY = 0;
var _ng_animId = null;
var _ng_time = 0;

window.drawNetworkGraph = async function(machines) {
    var canvas = document.getElementById('networkCanvas');
    if (!canvas) return;
    var loadingEl = document.getElementById('networkGraphLoading');
    if (loadingEl) loadingEl.style.display = 'none';

    var alertCounts = {};
    if (machines && machines.length > 0) {
        try {
            var results = await Promise.all([
                fetch('/api/threats?limit=500').then(function(r){return r.json();}),
                fetch('/api/vulns?limit=500').then(function(r){return r.json();}),
                fetch('/api/yara?limit=500').then(function(r){return r.json();})
            ]);
            var countAlerts = function(data, sevField) {
                (Array.isArray(data) ? data : []).forEach(function(item) {
                    var mid = item.machine_id || item.hostname;
                    if (!mid) return;
                    if (!alertCounts[mid]) alertCounts[mid] = {threats:0, vulns:0, yara:0};
                    var sev = (item.severity || item[sevField] || '').toUpperCase();
                    if (sev === 'CRITICAL') {
                        if (sevField === 'threats') alertCounts[mid].threats++;
                        else if (sevField === 'vulns') alertCounts[mid].vulns++;
                        else if (sevField === 'yara') alertCounts[mid].yara++;
                    }
                });
            };
            countAlerts(results[0], 'threats');
            countAlerts(results[1], 'vulns');
            countAlerts(results[2], 'yara');
        } catch(e) {}
    }

    var ctx = canvas.getContext('2d');
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    var W = rect.width;
    var H = rect.height;

    _ng_zoom = 1.0;
    _ng_offsetX = 0;
    _ng_offsetY = 0;

    var nodes = [];
    nodes.push({id:'server', label:'SERVER', x:W/2, y:H/2, radius:10, color:'#00d4aa', glowColor:'rgba(0,212,170,0.6)', isServer:true, online:true});

    if (machines && machines.length > 0) {
        var onlineNodes = machines.filter(function(m){return m.is_online==1;});
        var offlineNodes = machines.filter(function(m){return m.is_online!=1;});
        onlineNodes.forEach(function(m,i){
            var angle = (i/Math.max(onlineNodes.length,1))*Math.PI*2 - Math.PI/2;
            var dist = Math.min(W,H)*0.3;
            nodes.push({id:m.machine_id, label:m.hostname||m.machine_id, ip:m.ip_address, x:W/2+Math.cos(angle)*dist, y:H/2+Math.sin(angle)*dist, radius:6, color:'#3399ff', glowColor:'rgba(51,153,255,0.6)', isServer:false, online:true, angle:angle, dist:dist, orbitSpeed:0.0002+Math.random()*0.0003, alerts:alertCounts[m.machine_id]||{threats:0,vulns:0,yara:0}});
        });
        offlineNodes.forEach(function(m,i){
            var angle = (i/Math.max(offlineNodes.length,1))*Math.PI*2 + Math.PI/3;
            var dist = Math.min(W,H)*0.4;
            nodes.push({id:m.machine_id, label:m.hostname||m.machine_id, ip:m.ip_address, x:W/2+Math.cos(angle)*dist, y:H/2+Math.sin(angle)*dist, radius:4, color:'#ff4444', glowColor:'rgba(255,68,68,0.3)', isServer:false, online:false, angle:angle, dist:dist, orbitSpeed:0.0001, alerts:alertCounts[m.machine_id]||{threats:0,vulns:0,yara:0}});
        });
    }

    window.networkGraphNodes = nodes;
    if (_ng_animId) cancelAnimationFrame(_ng_animId);

    var stars = [];
    for (var i=0;i<100;i++) stars.push({x:Math.random()*W*3-W, y:Math.random()*H*3-H, r:Math.random()*1.2+0.3, twinkle:Math.random()*Math.PI*2, speed:0.01+Math.random()*0.03});

    var particles = [];
    for (var i=0;i<40;i++) particles.push({angle:Math.random()*Math.PI*2, dist:Math.random()*Math.min(W,H)*0.4+10, speed:0.003+Math.random()*0.008, size:Math.random()*2+1});

    function animate(ts) {
        _ng_time = ts*0.001;
        ctx.save();
        ctx.fillStyle = '#080e14';
        ctx.fillRect(0,0,W,H);
        var cx = W/2, cy = H/2;
        ctx.translate(cx,cy);
        ctx.scale(_ng_zoom,_ng_zoom);
        ctx.translate(-cx+_ng_offsetX/_ng_zoom, -cy+_ng_offsetY/_ng_zoom);

        stars.forEach(function(s){
            var sx=((s.x%(W*3))+W*3)%(W*3)-W, sy=((s.y%(H*3))+H*3)%(H*3)-H;
            s.twinkle+=s.speed;
            var alpha=0.3+Math.sin(s.twinkle)*0.4+0.4;
            ctx.beginPath();ctx.arc(sx,sy,s.r,0,Math.PI*2);
            ctx.fillStyle='rgba(255,255,255,'+alpha+')';ctx.fill();
        });

        particles.forEach(function(p){p.angle+=p.speed;p.x=W/2+Math.cos(p.angle)*p.dist;p.y=H/2+Math.sin(p.angle)*p.dist;});

        var serverNode = null;
        for (var i=0;i<nodes.length;i++) if (nodes[i].isServer) {serverNode=nodes[i]; break;}
        if (serverNode) {
            nodes.forEach(function(node){
                if (node.isServer) return;
                var alpha=node.online?0.25:0.08;
                ctx.beginPath();ctx.moveTo(serverNode.x,serverNode.y);ctx.lineTo(node.x,node.y);
                ctx.strokeStyle=node.online?'rgba(51,153,255,'+alpha+')':'rgba(255,68,68,'+alpha+')';
                ctx.lineWidth=node.online?1:0.5;ctx.setLineDash([4,8]);ctx.stroke();ctx.setLineDash([]);
            });
        }

        particles.forEach(function(p){
            if (serverNode) {
                var dx=serverNode.x-p.x, dy=serverNode.y-p.y;
                var dist=Math.sqrt(dx*dx+dy*dy);
                if (dist<Math.min(W,H)*0.45) {
                    var alpha=0.4+Math.sin(_ng_time*2+p.angle)*0.3;
                    ctx.beginPath();ctx.arc(p.x,p.y,p.size,0,Math.PI*2);
                    ctx.fillStyle='rgba(0,212,170,'+alpha+')';ctx.fill();
                    var grad=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,p.size*4);
                    grad.addColorStop(0,'rgba(0,212,170,'+(alpha*0.8)+')');grad.addColorStop(1,'rgba(0,212,170,0)');
                    ctx.beginPath();ctx.arc(p.x,p.y,p.size*4/_ng_zoom,0,Math.PI*2);ctx.fillStyle=grad;ctx.fill();
                }
            }
        });

        nodes.forEach(function(node){
            var r=node.radius;
            var glowGrad=ctx.createRadialGradient(node.x,node.y,r*0.3,node.x,node.y,r*3.5);
            glowGrad.addColorStop(0,node.glowColor||'rgba(0,212,170,0.4)');glowGrad.addColorStop(1,'rgba(0,0,0,0)');
            ctx.beginPath();ctx.arc(node.x,node.y,r*3.5,0,Math.PI*2);ctx.fillStyle=glowGrad;ctx.fill();
            var innerGlow=ctx.createRadialGradient(node.x,node.y,0,node.x,node.y,r*1.8);
            innerGlow.addColorStop(0,'rgba(255,255,255,0.8)');innerGlow.addColorStop(0.3,node.color);innerGlow.addColorStop(1,'rgba(0,0,0,0)');
            ctx.beginPath();ctx.arc(node.x,node.y,r*1.8,0,Math.PI*2);ctx.fillStyle=innerGlow;ctx.fill();
            ctx.beginPath();ctx.arc(node.x,node.y,r,0,Math.PI*2);ctx.fillStyle='#ffffff';ctx.fill();

            if (!node.isServer && node.alerts) {
                var alertTypes=[];
                if (node.alerts.threats>0) alertTypes.push({emoji:'⚠',label:'Threats'});
                if (node.alerts.vulns>0) alertTypes.push({emoji:'🐞',label:'Vulns'});
                if (node.alerts.yara>0) alertTypes.push({emoji:'🦠',label:'YARA'});
                var iconCount=alertTypes.length, iconSize=10, iconGap=3;
                var totalWidth=iconCount*iconSize+(iconCount-1)*iconGap;
                var startX=node.x-totalWidth/2+iconSize/2, iconY=node.y-r-10;
                if (iconCount>0){
                    var glowW=totalWidth+12, glowH=iconSize+10;
                    var glowGrad2=ctx.createRadialGradient(node.x,iconY,2,node.x,iconY,glowW);
                    glowGrad2.addColorStop(0,'rgba(255,50,50,0.4)');glowGrad2.addColorStop(1,'rgba(0,0,0,0)');
                    ctx.beginPath();ctx.ellipse(node.x,iconY,glowW,glowH,0,0,Math.PI*2);ctx.fillStyle=glowGrad2;ctx.fill();
                }
                alertTypes.forEach(function(at,i){
                    var ix=startX+i*(iconSize+iconGap);
                    ctx.beginPath();ctx.arc(ix,iconY,iconSize/2+2,0,Math.PI*2);
                    ctx.fillStyle='rgba(220,40,40,0.85)';ctx.fill();ctx.strokeStyle='#ff6666';ctx.lineWidth=1;ctx.stroke();
                    ctx.font=(iconSize-2)+'px "Segoe UI Emoji", "Apple Color Emoji", sans-serif';
                    ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(at.emoji,ix,iconY);
                });
            }

            if (node.isServer) {
                ctx.font='bold 11px "Segoe UI", sans-serif';ctx.fillStyle='#00d4aa';ctx.textAlign='center';
                ctx.fillText(node.label,node.x,node.y+r+16);
            } else if (node.online) {
                ctx.font='9px "Segoe UI", sans-serif';ctx.fillStyle='#c8d8e8';ctx.textAlign='center';
                var shortLabel=node.label.length>12?node.label.substring(0,11)+'…':node.label;
                ctx.fillText(shortLabel,node.x,node.y+r+12);
                if (node.ip){ctx.font='8px monospace';ctx.fillStyle='#6a8aaa';ctx.fillText(node.ip,node.x,node.y+r+22);}
            } else {
                ctx.font='8px "Segoe UI", sans-serif';ctx.fillStyle='#996666';ctx.textAlign='center';
                var shortLabel=node.label.length>12?node.label.substring(0,11)+'…':node.label;
                ctx.fillText(shortLabel,node.x,node.y+r+10);
            }
            node.clickRadius=r+12;
        });

        window.networkGraphNodes = nodes;
        ctx.restore();
        _ng_animId = requestAnimationFrame(animate);
    }

    animate(0);

    canvas.onwheel = function(e) {
        e.preventDefault();
        var zoomFactor=e.deltaY<0?1.1:0.9;
        var newZoom=Math.max(0.3,Math.min(5.0,_ng_zoom*zoomFactor));
        var rect=canvas.getBoundingClientRect();
        var mx=e.clientX-rect.left-W/2, my=e.clientY-rect.top-H/2;
        var scaleChange=newZoom/_ng_zoom;
        _ng_offsetX=mx-scaleChange*(mx-_ng_offsetX);
        _ng_offsetY=my-scaleChange*(my-_ng_offsetY);
        _ng_zoom=newZoom;
    };

    canvas.onmousedown = function(e) {
        _ng_dragging=true;_ng_dragStartX=e.clientX;_ng_dragStartY=e.clientY;
        _ng_dragOffX=_ng_offsetX;_ng_dragOffY=_ng_offsetY;canvas.style.cursor='grabbing';
    };
    canvas.onmousemove = function(e) {
        if(!_ng_dragging) return;
        _ng_offsetX=_ng_dragOffX+(e.clientX-_ng_dragStartX);
        _ng_offsetY=_ng_dragOffY+(e.clientY-_ng_dragStartY);
    };
    canvas.onmouseup = function(){_ng_dragging=false;canvas.style.cursor='grab';};
    canvas.onmouseleave = function(){_ng_dragging=false;canvas.style.cursor='grap';};
    canvas.ondblclick = function(){_ng_zoom=1.0;_ng_offsetX=0;_ng_offsetY=0;};

    canvas.onclick = function(e) {
        if(_ng_dragging) return;
        var rect=canvas.getBoundingClientRect();
        var mx=e.clientX-rect.left, my=e.clientY-rect.top;
        var cx=W/2, cy=H/2;
        var wx=cx+(mx-cx-_ng_offsetX)/_ng_zoom, wy=cy+(my-cy-_ng_offsetY)/_ng_zoom;
        for (var i=0;i<window.networkGraphNodes.length;i++) {
            var node=window.networkGraphNodes[i];
            if (node.isServer) continue;
            var dx=node.x-wx, dy=node.y-wy;
            var dist=Math.sqrt(dx*dx+dy*dy);
            var hitRadius=node.clickRadius||(node.radius+12);
            if (dist<=hitRadius) { window.selectMachine(node.id); return; }
        }
    };
};