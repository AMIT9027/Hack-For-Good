function updateMap()
{

fetch("/data.json")
.then(response=>response.json())
.then(rsp=>
{
console.log(rsp.data)
rsp.data.forEach(element => {
    latitude=element.latitude;
    longitude=element.longitude;
    
    cases=element.infected;
    if (cases>25)
    {

     color="rgb(255,0,0)"   
    }
    else
    {
        color='rgb(${cases},0,0)'; 

    }
new mapboxgl.Marker({

     draggable:false,
     color:color
})
.setLngLat([longitude,latitude])
.addTo(map);




});
map.addControl(
    new mapboxgl.GeolocateControl({
    positionOptions: {
    enableHighAccuracy: true
    },
    trackUserLocation: true
    })
    );
})

}

updateMap();