// Code for canvas
// Source: http://www.williammalone.com/articles/create-html5-canvas-javascript-drawing-app/
// Modified by PinkDraconian

canvas = document.getElementById("handwrittenDigitCanvas")

context = canvas.getContext("2d");

let paint;
canvas.onmousedown = function(e) {
    const mouseX = e.pageX - this.offsetLeft;
    const mouseY = e.pageY - this.offsetTop;

    paint = true;
    addClick(mouseX, mouseY);
    redraw();
};

canvas.onmousemove = function(e) {
    if(paint){
        const mouseX = e.pageX - this.offsetLeft;
        const mouseY = e.pageY - this.offsetTop;
        addClick(mouseX, mouseY, true);
        redraw();
    }
};

canvas.onmouseup = () => {
    paint = false;
};

canvas.onmouseleave = function() {
    paint = false;
};

const clickX = [];
const clickY = [];
const clickDrag = [];

function addClick(x, y, dragging)
{
    clickX.push(x);
    clickY.push(y);
    clickDrag.push(dragging);
}

function redraw() {
    context.clearRect(0, 0, context.canvas.width, context.canvas.height); // Clears the canvas

    context.strokeStyle = "#df4b26";
    context.lineJoin = "round";
    context.lineWidth = 5;

    for(let i=0; i < clickX.length; i++) {
        context.beginPath();
        if(clickDrag[i] && i){
            context.moveTo(clickX[i-1], clickY[i-1]);
        }else{
            context.moveTo(clickX[i]-1, clickY[i]);
        }
        context.lineTo(clickX[i], clickY[i]);
        context.closePath();
        context.stroke();
    }
}
