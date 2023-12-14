import { DisplayGraph} from "./AlertsTypes"
import G6, { Graph, TreeGraph } from '@antv/g6';
import { log } from "console";
import path, { relative } from "path";
import { memo, useEffect, useRef } from "react";
import ReactDOM from 'react-dom';
import { categoryToColor, labelCategory, labelDisplay, labelImage } from "./ResourceMappings";

type RuleGraphProps={
    ruleGraph: DisplayGraph,
    graphEventListner?:(graph:Graph)=>void
}

export type GraphNodeType={
  id:string,
  label:string,
  display_id:string,
  style:any,
  icon:any,
  stateStyles:any
}

export default memo(function RuleGraph({ruleGraph,graphEventListner}:RuleGraphProps){
    const {node_info,adjacency_list} = ruleGraph;
   
    const canvasRef = useRef(null);

    const data = {
      nodes:new Array<GraphNodeType>,
      edges:new Array<{edge_id:number | null,source:string,target:string,style:any,stateStyles:any}>
    }

    useEffect(()=>{
      if(!node_info || !adjacency_list){
        return;
      }
      const container = ReactDOM.findDOMNode(canvasRef.current) as HTMLElement;
      const width = container?.scrollWidth || 500;
      const height = container?.scrollHeight || 400;

      Object.values(node_info)?.forEach((node)=>{
        if(!data.nodes.some(n=>n.id===node.resource_id.toString())){
          data.nodes.push({
            id: node.resource_id.toString(),
            label: labelDisplay(node.node_label),
            display_id: node.display_id,
            style:{
                  fill:categoryToColor[labelCategory(node.node_label)],
                  stroke:categoryToColor[labelCategory(node.node_label)],
                  lineWidth: 3,
                },
            icon:{
              show:true,
              img: labelImage(node.node_label),
              width: 20,
              height: 20,
            },
            stateStyles:{
              selected:{
                fill:categoryToColor[labelCategory(node.node_label)],
                stroke: null,
                shadowBlur: 20,
                shadowColor: categoryToColor[labelCategory(node.node_label)],
              },
              hover:{
                cursor: "pointer",
                fillOpacity:0.8,
                lineWidth:0
              },
            }
          });
        }
      })
  
      Object.keys(adjacency_list)?.forEach(src=>{
        adjacency_list[src].forEach(edge=>{
          const dest = edge.target_resource_id
          const isDotted = edge.make_dotted
          const edgeID = edge.id
          if(!data.edges.some(edge=>edge.source===src && edge.target===dest.toString())){
            data.edges.push({
              edge_id:edgeID,
              source:src,
              target: dest.toString(),
              style:{
                lineWidth: 1,
                stroke: `l(0) 0:${categoryToColor[labelCategory(node_info[src].node_label)]} 1:${categoryToColor[labelCategory(node_info[dest.toString()].node_label)]}`,
                lineDash: isDotted ? [6,4] : null,
              },
              stateStyles:{
                hover:{
                  cursor:"pointer"
                },
                selected:{
                  shadowColor: "grey",
                  stroke: `l(0) 0:${categoryToColor[labelCategory(node_info[src].node_label)]} 1:${categoryToColor[labelCategory(node_info[dest.toString()].node_label)]}`,
                  shadowBlur:20,
                  lineWidth: 2
                }
              }
            })
          }
        })
      })

      const graph = new G6.Graph({
      container: container,
      width,
      height,
      // fitView:true,
      fitCenter:true,
      
      modes: {
        default: [
          {
            type: 'tooltip',
            offset: 20,
            formatText: function formatText(model:any) {
              const text = model.display_id;
              return text;
            }
          },
          'drag-canvas',
          'zoom-canvas',
        ],
      },
      // plugins:[tooltip],
      
      defaultNode: {
        size: 40,
        anchorPoints: [
          [0, 0.5],
          [1, 0.5],
        ],
        labelCfg:{
            position: "bottom",
            offset: 5,
            style:{
              fonntSize: 20
            }
        },
      }, 
      defaultEdge: {
        type: 'polyline',
        linkCenter:true,
        style:{
          radius:20,
          lineAppendWidth:8,
          
        }
      },
      layout:{
        type: 'dagre',
        rankdir: 'LR',
        controlPoints: true,
        
        nodesep: 30,
        ranksep: 30
      }
    });

    graph.data(data);
    graph.render();
    
    // addTreeGraphChild(left_side_paths,graph);
    // addTreeGraphChild(right_side_paths,graph);

    // graph.fitView();
    // graph.refresh();
    // graph.refreshPositions();
    

    graphEventListner && graphEventListner(graph)

    if (typeof window !== 'undefined')
      window.onresize = () => {
        if (!graph || graph.get('destroyed')) return;
        if (!container || !container.scrollWidth || !container.scrollHeight) return;
        graph.changeSize(container.scrollWidth, container.scrollHeight);
      };
      return ()=>{
        graph.destroy();
      }
      
    })

    if(!node_info || !adjacency_list){
      return null
    }
    return(
        <div className="relative grow" ref={canvasRef}></div>
    )
})
