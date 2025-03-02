import React from 'react'
import classes from '../components/Modal.module.css'

const Modal = (props) => {
    function stopPropagatingHandler(event){
        event.stopPropagation();
    }
  return (
    <>
      <div className={classes.backdrop} onClick={props.onClose}>
        <dialog open  className={classes.modal} onClick={stopPropagatingHandler}>
            {props.children}
        </dialog>
      </div>
    </>
  )
}

export default Modal
