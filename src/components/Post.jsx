import React from 'react'
import classes from '../components/Post.module.css'

const Post = (props) => {
   
  return (
    <li className={classes.post}>
      <p className={classes.author}>{props.name}</p>
      
      <p className={classes.text}>{props.course}</p>
    </li>
  )
}

export default Post
